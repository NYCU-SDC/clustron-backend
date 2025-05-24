package main

import (
	"clustron-backend/internal"
	"clustron-backend/internal/auth"
	"clustron-backend/internal/config"
	"clustron-backend/internal/group"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/setting"
	"clustron-backend/internal/trace"
	"clustron-backend/internal/user"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/middleware"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.6.1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var AppName = "no-app-name"

var Version = "no-version"

var BuildTime = "no-build-time"

var CommitHash = "no-commit-hash"

func main() {
	AppName = os.Getenv("APP_NAME")
	if AppName == "" {
		AppName = "clustron-backend"
	}

	if BuildTime == "no-build-time" {
		now := time.Now()
		BuildTime = "not provided (now: " + now.Format(time.RFC3339) + ")"
	}

	appMetadata := []zap.Field{
		zap.String("app_name", AppName),
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("commit_hash", CommitHash),
	}

	cfg, cfgLog := config.Load()
	err := cfg.Validate()
	if err != nil {
		if errors.Is(err, config.ErrDatabaseURLRequired) {
			title := "Database URL is required"
			message := "Please set the DATABASE_URL environment variable or provide a config file with the database_url key."
			message = EarlyApplicationFailed(title, message)
			log.Fatal(message)
		} else {
			log.Fatalf("Failed to validate config: %v, exiting...", err)
		}
	}

	logger, err := initLogger(&cfg, appMetadata)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v, exiting...", err)
	}

	cfgLog.FlushToZap(logger)

	if cfg.Secret == config.DefaultSecret && !cfg.Debug {
		logger.Warn("Default secret detected in production environment, replace it with a secure random string")
		cfg.Secret = uuid.New().String()
	}

	logger.Info("Application initialization", zap.Bool("debug", cfg.Debug), zap.String("host", cfg.Host), zap.String("port", cfg.Port))

	logger.Info("Starting database migration...")

	err = databaseutil.MigrationUp(cfg.MigrationSource, cfg.DatabaseURL, logger)
	if err != nil {
		logger.Fatal("Failed to run database migration", zap.Error(err))
	}

	dbPool, err := initDatabasePool(cfg.DatabaseURL)
	if err != nil {
		logger.Fatal("Failed to initialize database pool", zap.Error(err))
	}
	defer dbPool.Close()

	shutdown, err := initOpenTelemetry(AppName, Version, BuildTime, CommitHash, cfg.OtelCollectorUrl)
	if err != nil {
		logger.Fatal("Failed to initialize OpenTelemetry", zap.Error(err))
	}

	validator := internal.NewValidator()
	problemWriter := internal.NewProblemWriter()

	// Service
	userService := user.NewService(logger, dbPool)
	jwtService := jwt.NewService(logger, cfg.Secret, 15*time.Minute, 24*time.Hour, userService, dbPool)
	settingService := setting.NewService(logger, dbPool)
	groupService := group.NewService(logger, dbPool, userService)

	// Handler
	authHandler := auth.NewHandler(cfg, logger, validator, problemWriter, userService, jwtService, settingService)
	jwtHandler := jwt.NewHandler(logger, validator, problemWriter, jwtService)
	settingHandler := setting.NewHandler(logger, validator, problemWriter, settingService)
	groupHandler := group.NewHandler(logger, validator, problemWriter, groupService, groupService)

	// Basic Middleware
	traceMiddleware := trace.NewMiddleware(logger, cfg.Debug)
	recovered := middleware.NewSet(traceMiddleware.RecoverMiddleware)
	traced := recovered.Append(traceMiddleware.TraceMiddleWare)

	// Auth Middleware
	jwtMiddleware := jwt.NewMiddleware(jwtService, logger)
	authMiddleware := traced.Append(jwtMiddleware.HandlerFunc)

	// HTTP Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/login/oauth/{provider}", traced.HandlerFunc(authHandler.Oauth2Start))
	mux.HandleFunc("GET /api/oauth/{provider}/callback", traced.HandlerFunc(authHandler.Callback))
	mux.HandleFunc("GET /api/oauth/debug/token", traced.HandlerFunc(authHandler.DebugToken))
	mux.HandleFunc("GET /api/refreshToken/{refreshToken}", traced.HandlerFunc(jwtHandler.RefreshToken))

	mux.HandleFunc("GET /api/settings", authMiddleware.HandlerFunc(settingHandler.GetUserSettingHandler))
	mux.HandleFunc("PUT /api/settings", authMiddleware.HandlerFunc(settingHandler.UpdateUserSettingHandler))
	mux.HandleFunc("GET /api/publickey", authMiddleware.HandlerFunc(settingHandler.GetUserPublicKeysHandler))
	mux.HandleFunc("POST /api/publickey", authMiddleware.HandlerFunc(settingHandler.AddUserPublicKeyHandler))
	mux.HandleFunc("DELETE /api/publickey", authMiddleware.HandlerFunc(settingHandler.DeletePublicKeyHandler))

	mux.HandleFunc("GET /api/groups", authMiddleware.HandlerFunc(groupHandler.GetAllHandler))
	mux.HandleFunc("POST /api/groups", authMiddleware.HandlerFunc(groupHandler.CreateHandler))
	mux.HandleFunc("GET /api/groups/{group_id}", authMiddleware.HandlerFunc(groupHandler.GetByIDHandler))
	mux.HandleFunc("POST /api/groups/{group_id}/archive", authMiddleware.HandlerFunc(groupHandler.ArchiveHandler))
	mux.HandleFunc("POST /api/groups/{group_id}/unarchive", authMiddleware.HandlerFunc(groupHandler.UnarchiveHandler))

	mux.HandleFunc("GET /api/groups/{group_id}/members", authMiddleware.HandlerFunc(groupHandler.ListGroupMembersPagedHandler))
	mux.HandleFunc("POST /api/groups/{group_id}/members", authMiddleware.HandlerFunc(groupHandler.AddGroupMemberHandler))
	mux.HandleFunc("DELETE /api/groups/{group_id}/members/{user_id}", authMiddleware.HandlerFunc(groupHandler.RemoveGroupMemberHandler))
	mux.HandleFunc("POST /api/groups/{group_id}/members/{user_id}", authMiddleware.HandlerFunc(groupHandler.UpdateGroupMemberHandler))
	mux.HandleFunc("GET /api/groups/roles", authMiddleware.HandlerFunc(groupHandler.ListGroupRolesHandler))

	// handle interrupt signal
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:    cfg.Host + ":" + cfg.Port,
		Handler: mux,
	}

	go func() {
		logger.Info("Starting listening request", zap.String("host", cfg.Host), zap.String("port", cfg.Port))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("Fail to start server with error", zap.Error(err))
		}
	}()

	// wait for context close
	<-ctx.Done()
	logger.Info("Shutting down gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server forced to shutdown", zap.Error(err))
	}

	otelCtx, otelCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer otelCancel()
	if err := shutdown(otelCtx); err != nil {
		logger.Error("Forced to shutdown OpenTelemetry", zap.Error(err))
	}

	logger.Info("Successfully shutdown")
}

func initLogger(cfg *config.Config, appMetadata []zap.Field) (*zap.Logger, error) {
	var err error
	var logger *zap.Logger
	if cfg.Debug {
		logger, err = logutil.ZapDevelopmentConfig().Build()
		if err != nil {
			return nil, err
		}
		logger.Info("Running in debug mode", appMetadata...)
	} else {
		logger, err = logutil.ZapProductionConfig().Build()
		if err != nil {
			return nil, err
		}

		logger = logger.With(appMetadata...)
	}
	defer func() {
		err := logger.Sync()
		if err != nil {
			zap.S().Errorw("Failed to sync logger", zap.Error(err))
		}
	}()

	return logger, nil
}

func initDatabasePool(databaseURL string) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}

	dbPool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, err
	}
	return dbPool, nil
}

func initOpenTelemetry(appName, version, buildTime, commitHash, otelCollectorUrl string) (func(context.Context) error, error) {
	ctx := context.Background()

	serviceName := semconv.ServiceNameKey.String(appName)
	serviceVersion := semconv.ServiceVersionKey.String(version)
	serviceNamespace := semconv.ServiceNamespaceKey.String("example")
	serviceCommitHash := semconv.ServiceVersionKey.String(commitHash)

	res, err := resource.New(ctx,
		resource.WithAttributes(
			serviceName,
			serviceVersion,
			serviceNamespace,
			serviceCommitHash,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	options := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	}

	if otelCollectorUrl != "" {
		conn, err := initGrpcConn(otelCollectorUrl)
		if err != nil {
			return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
		}

		traceExporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithGRPCConn(conn))
		if err != nil {
			return nil, fmt.Errorf("failed to create trace exporter: %w", err)
		}

		bsp := sdktrace.NewBatchSpanProcessor(traceExporter)
		options = append(options, sdktrace.WithSpanProcessor(bsp))
	}

	tracerProvider := sdktrace.NewTracerProvider(options...)

	otel.SetTracerProvider(tracerProvider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tracerProvider.Shutdown, nil
}

func initGrpcConn(target string) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	return conn, nil
}

func EarlyApplicationFailed(title, action string) string {
	result := `
-----------------------------------------
Application Failed to Start
-----------------------------------------

# What's wrong?
%s

# How to fix it?
%s

`

	result = fmt.Sprintf(result, title, action)
	return result
}
