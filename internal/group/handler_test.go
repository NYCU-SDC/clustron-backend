package group_test

// Todo: Move test to service layer
//func TestHandler_CreateHandler(t *testing.T) {
//	testCases := []struct {
//		name       string
//		user       jwt.User
//		body       group.CreateRequest
//		setupMocks func(*mocks.Store)
//		wantStatus int
//	}{
//		{
//			name: "Should create group for admin",
//			user: jwt.User{
//				Role: pgtype.Text{String: "admin", Valid: true},
//			},
//			body: group.CreateRequest{
//				Title:       "Test Group",
//				Description: "Test Description",
//			},
//			setupMocks: func(store *mocks.Store) {
//				store.On("Create", mock.Anything, mock.Anything).Return(group.Group{
//					ID:          uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
//					Title:       "Test Group",
//					Description: pgtype.Text{String: "Test Description", Valid: true},
//					IsArchived:  pgtype.Bool{Valid: true},
//					CreatedAt:   pgtype.Timestamptz{Time: time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC)},
//					UpdatedAt:   pgtype.Timestamptz{Time: time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC)},
//				}, nil)
//				store.On("GetGroupRoleByID", mock.Anything, uuid.MustParse(string(group.RoleOwner))).Return(group.GroupRole{
//					ID:          uuid.MustParse(string(group.RoleOwner)),
//					RoleName:        pgtype.Text{String: "group_owner", Valid: true},
//					AccessLevel: "GROUP_OWNER",
//				}, nil)
//			},
//			wantStatus: http.StatusCreated,
//		},
//		{
//			name: "Should create group for organizer",
//			user: jwt.User{
//				Role: pgtype.Text{String: "organizer", Valid: true},
//			},
//			body: group.CreateRequest{
//				Title:       "Test Group",
//				Description: "Test Description",
//			},
//			setupMocks: func(store *mocks.Store) {
//				store.On("Create", mock.Anything, mock.Anything).Return(group.Group{
//					ID:          uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
//					Title:       "Test Group",
//					Description: pgtype.Text{String: "Test Description", Valid: true},
//					IsArchived:  pgtype.Bool{Valid: true},
//					CreatedAt:   pgtype.Timestamptz{Time: time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC)},
//					UpdatedAt:   pgtype.Timestamptz{Time: time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC)},
//				}, nil)
//				store.On("GetGroupRoleByID", mock.Anything, uuid.MustParse(string(group.RoleOwner))).Return(group.GroupRole{
//					ID:          uuid.MustParse(string(group.RoleOwner)),
//					RoleName:        pgtype.Text{String: "group_owner", Valid: true},
//					AccessLevel: "GROUP_OWNER",
//				}, nil)
//			},
//
//			wantStatus: http.StatusCreated,
//		},
//		{
//			name: "Should not create group for user",
//			user: jwt.User{
//				Role: pgtype.Text{String: "user", Valid: true},
//			},
//			body: group.CreateRequest{
//				Title:       "Test Group",
//				Description: "Test Description",
//			},
//			setupMocks: func(store *mocks.Store) {
//
//			},
//			wantStatus: http.StatusForbidden,
//		},
//	}
//
//	for _, tc := range testCases {
//		t.Run(tc.name, func(t *testing.T) {
//			logger, err := zap.NewDevelopment()
//			if err != nil {
//				t.Fatalf("failed to create logger: %v", err)
//			}
//			store := mocks.NewStore(t)
//			auth := mocks.NewAuth(t)
//
//			if tc.setupMocks != nil {
//				tc.setupMocks(store)
//			}
//			h := group.NewHandler(logger, validator.New(), problem.New(), store, auth)
//
//			requestBody, err := json.Marshal(tc.body)
//			if err != nil {
//				t.Fatalf("failed to marshal request body: %v", err)
//			}
//			r := httptest.NewRequest(http.MethodPost, "/groups", bytes.NewReader(requestBody))
//			r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, tc.user))
//			w := httptest.NewRecorder()
//
//			h.CreateHandler(w, r)
//
//			assert.Equal(t, tc.wantStatus, w.Code)
//		})
//	}
//}
//
//func TestHandler_GetAllHandler(t *testing.T) {
//	groups := []group.UserScope{
//		// organizer, and user in this group
//		{
//			Group: group.Group{
//				ID:          uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
//				Title:       "Test Group 1",
//				Description: pgtype.Text{String: "Test Description 1", Valid: true},
//			},
//		},
//		// organizer in this group
//		{
//			Group: group.Group{
//				ID:          uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970f"),
//				Title:       "Test Group 2",
//				Description: pgtype.Text{String: "Test Description 2", Valid: true},
//			},
//		},
//		{
//			Group: group.Group{
//				ID:          uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970a"),
//				Title:       "Test Group 3",
//				Description: pgtype.Text{String: "Test Description 3", Valid: true},
//			},
//		},
//	}
//	groupRoles := []group.GroupRole{
//		{
//			ID:          uuid.MustParse("bd1a0054-88f5-4e30-92ac-eb4eb7ac734a"),
//			RoleName:        pgtype.Text{String: "organizer", Valid: true},
//			AccessLevel: "organizer",
//		},
//		{
//			ID:          uuid.MustParse("bd1a0054-88f5-4e30-92ac-eb4eb7ac734b"),
//			RoleName:        pgtype.Text{String: "user", Valid: true},
//			AccessLevel: "user",
//		},
//	}
//
//	testCases := []struct {
//		name       string
//		user       jwt.User
//		setupMocks func(*mocks.Store)
//		wantStatus int
//		wantResult []string
//	}{
//		{
//			name: "Should get all groups for admin",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e9"),
//				RoleName: pgtype.Text{String: "admin", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store) {
//				store.On("ListWithUserScope", mock.Anything, jwt.User{
//					ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e9"),
//					RoleName: pgtype.Text{String: "admin", Valid: true},
//				}, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(groups, nil)
//				//store.On("ListPaged", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(groups, nil)
//				//store.On("GetAllGroupCount", mock.Anything).Return(len(groups), nil)
//				//store.On("ListUserMemberships", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e9")).Return([]group.GetUserAllMembershipRow{}, nil)
//			},
//			wantStatus: http.StatusOK,
//			wantResult: []string{
//				"Test Group 1",
//				"Test Group 2",
//				"Test Group 3",
//			},
//		},
//		{
//			name: "Should get limited groups for organizer",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e3"),
//				RoleName: pgtype.Text{String: "organizer", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store) {
//				store.On("listByUserID", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e3"), mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(groups[0:2],
//					[]group.GroupRole{groupRoles[0], groupRoles[0]}, nil)
//				store.On("CountByUser", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e3")).Return(2, nil)
//			},
//			wantStatus: http.StatusOK,
//			wantResult: []string{
//				"Test Group 1",
//				"Test Group 2",
//			},
//		},
//		{
//			name: "Should get limited groups for user",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e2"),
//				RoleName: pgtype.Text{String: "user", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store) {
//				store.On("listByUserID", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e2"), mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(groups[0:1],
//					[]group.GroupRole{groupRoles[1]}, nil)
//				store.On("CountByUser", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e2")).Return(1, nil)
//			},
//			wantStatus: http.StatusOK,
//			wantResult: []string{
//				"Test Group 1",
//			},
//		},
//	}
//
//	for _, tc := range testCases {
//		t.Run(tc.name, func(t *testing.T) {
//			logger, err := zap.NewDevelopment()
//			if err != nil {
//				t.Fatalf("failed to create logger: %v", err)
//			}
//			store := mocks.NewStore(t)
//			auth := mocks.NewAuth(t)
//			h := group.NewHandler(logger, validator.New(), problem.New(), store, auth)
//
//			if tc.setupMocks != nil {
//				tc.setupMocks(store)
//			}
//
//			r := httptest.NewRequest(http.MethodGet, "/groups", nil)
//			r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, tc.user))
//			w := httptest.NewRecorder()
//
//			h.GetAllHandler(w, r)
//
//			assert.Equal(t, tc.wantStatus, w.Code)
//
//			var got pagination.Response[group.Response]
//			err = json.Unmarshal(w.Body.Bytes(), &got)
//			if err != nil {
//				t.Fatalf("failed to unmarshal response body: %v", err)
//			}
//
//			for i, g := range got.Items {
//				assert.Equal(t, tc.wantResult[i], g.Title)
//			}
//		})
//	}
//}
//
//func TestHandler_GetByIDHandler(t *testing.T) {
//	groupID := uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")
//	testCases := []struct {
//		name       string
//		user       jwt.User
//		setupMocks func(store *mocks.Store)
//		wantStatus int
//	}{
//		{
//			name: "Should get group for admin",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e9"),
//				RoleName: pgtype.Text{String: "admin", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store) {
//				store.On("Get", mock.Anything, groupID).Return(group.Group{
//					Title:       "Test Group",
//					Description: pgtype.Text{String: "Test Description", Valid: true},
//				}, nil)
//				store.On("GetUserGroupRole", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e9"), groupID).Return(group.GroupRole{},
//					databaseutil.WrapDBErrorWithKeyValue(pgx.ErrNoRows, "membership", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", groupID.String(), "a9e0fd99-10de-4ad1-b519-e8430ed089e9"), zap.NewExample(), "get membership"),
//				)
//			},
//			wantStatus: http.StatusOK,
//		},
//		{
//			name: "Should get group for organizer in this group",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e7"),
//				RoleName: pgtype.Text{String: "organizer", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store) {
//				store.On("GetUserGroupByID", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e7"), groupID).Return(group.Group{
//					Title:       "Test Group",
//					Description: pgtype.Text{String: "Test Description", Valid: true},
//				}, nil)
//				store.On("GetUserGroupRole", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e7"), groupID).Return(group.GroupRole{
//					ID:          uuid.MustParse(string(group.RoleOwner)),
//					RoleName:        pgtype.Text{String: "organizer", Valid: true},
//					AccessLevel: string(group.AccessLevelOwner),
//				}, nil)
//			},
//			wantStatus: http.StatusOK,
//		},
//		{
//			name: "Should not get group for organizer not in this group",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e8"),
//				RoleName: pgtype.Text{String: "organizer", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store) {
//				store.On("GetUserGroupByID", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e8"), groupID).Return(group.Group{},
//					databaseutil.WrapDBErrorWithKeyValue(pgx.ErrNoRows, "membership", "(user_id, group_id)", fmt.Sprintf("(%s, %s)", "a9e0fd99-10de-4ad1-b519-e8430ed089e8", groupID), zap.NewExample(), "get membership"))
//			},
//
//			wantStatus: http.StatusNotFound,
//		},
//		{
//			name: "Should get group for user in this group",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e2"),
//				RoleName: pgtype.Text{String: "user", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store) {
//				store.On("GetUserGroupByID", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e2"), groupID).Return(group.Group{
//					Title:       "Test Group",
//					Description: pgtype.Text{String: "Test Description", Valid: true},
//				}, nil)
//				store.On("GetUserGroupRole", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e2"), groupID).Return(group.GroupRole{
//					ID:          uuid.MustParse(string(group.RoleStudent)),
//					RoleName:        pgtype.Text{String: "user", Valid: true},
//					AccessLevel: string(group.AccessLevelUser),
//				}, nil)
//			},
//			wantStatus: http.StatusOK,
//		},
//		{
//			name: "Should not get group for user not in this group",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e5"),
//				RoleName: pgtype.Text{String: "user", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store) {
//				store.On("GetUserGroupByID", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e5"), groupID).Return(group.Group{},
//					databaseutil.WrapDBErrorWithKeyValue(pgx.ErrNoRows, "membership", "(user_id, group_id)", fmt.Sprintf("(%s, %s)", "a9e0fd99-10de-4ad1-b519-e8430ed089e5", groupID), zap.NewExample(), "get membership"))
//			},
//			wantStatus: http.StatusNotFound,
//		},
//	}
//
//	for _, tc := range testCases {
//		t.Run(tc.name, func(t *testing.T) {
//			logger, err := zap.NewDevelopment()
//			if err != nil {
//				t.Fatalf("failed to create logger: %v", err)
//			}
//			store := mocks.NewStore(t)
//			auth := mocks.NewAuth(t)
//			h := group.NewHandler(logger, validator.New(), problem.New(), store, auth)
//
//			if tc.setupMocks != nil {
//				tc.setupMocks(store)
//			}
//
//			r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/groups/%s", groupID.String()), nil)
//			r.SetPathValue("group_id", groupID.String())
//			r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, tc.user))
//			w := httptest.NewRecorder()
//
//			h.GetByIDHandler(w, r)
//
//			assert.Equal(t, tc.wantStatus, w.Code)
//		})
//	}
//}
//
//func TestHandler_ArchiveHandler(t *testing.T) {
//	groupID := uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")
//
//	testCases := []struct {
//		name       string
//		user       jwt.User
//		setupMocks func(*mocks.Store, *mocks.Auth)
//		wantStatus int
//	}{
//		{
//			name: "Should archive group for admin",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e9"),
//				RoleName: pgtype.Text{String: "admin", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store, auth *mocks.Auth) {
//				store.On("GetUserGroupRole", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e9"), groupID).Return(
//					group.GroupRole{},
//					databaseutil.WrapDBErrorWithKeyValue(pgx.ErrNoRows, "membership", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", groupID.String(), "a9e0fd99-10de-4ad1-b519-e8430ed089e9"), zap.NewExample(), "get membership"),
//				)
//				store.On("Archive", mock.Anything, mock.Anything).Return(group.Group{
//					Title:       "Test Group",
//					Description: pgtype.Text{String: "Test Description", Valid: true},
//				}, nil)
//			},
//			wantStatus: http.StatusOK,
//		},
//		{
//			name: "Should archive group for organizer",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e3"),
//				RoleName: pgtype.Text{String: "organizer", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store, auth *mocks.Auth) {
//				auth.On("GetUserGroupAccessLevel", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e3"), groupID).Return(
//					string(group.AccessLevelOwner), nil)
//				store.On("GetUserGroupRole", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e3"), groupID).Return(
//					group.GroupRole{
//						ID:          uuid.MustParse(string(group.RoleOwner)),
//						RoleName:        pgtype.Text{String: "group_owner", Valid: true},
//						AccessLevel: string(group.AccessLevelOwner),
//					}, nil,
//				)
//				store.On("Archive", mock.Anything, mock.Anything).Return(group.Group{
//					Title:       "Test Group",
//					Description: pgtype.Text{String: "Test Description", Valid: true},
//				}, nil)
//			},
//			wantStatus: http.StatusOK,
//		},
//		{
//			name: "Should not archive group for organizer not in this group",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e5"),
//				RoleName: pgtype.Text{String: "organizer", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store, auth *mocks.Auth) {
//				auth.On("GetUserGroupAccessLevel", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e5"), groupID).Return(
//					"", databaseutil.WrapDBErrorWithKeyValue(pgx.ErrNoRows, "membership", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", "a9e0fd99-10de-4ad1-b519-e8430ed089e5", groupID.String()), zap.NewExample(), "get membership"))
//			},
//			wantStatus: http.StatusNotFound,
//		},
//		{
//			name: "Should not archive group for group-admin",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e7"),
//				RoleName: pgtype.Text{String: "user", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store, auth *mocks.Auth) {
//				auth.On("GetUserGroupAccessLevel", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e7"), groupID).Return(
//					string(group.AccessLevelAdmin), nil)
//			},
//			wantStatus: http.StatusForbidden,
//		},
//		{
//			name: "Should not archive group for user",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e2"),
//				RoleName: pgtype.Text{String: "user", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store, auth *mocks.Auth) {
//				auth.On("GetUserGroupAccessLevel", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e2"), groupID).Return(
//					string(group.AccessLevelUser), nil)
//			},
//			wantStatus: http.StatusForbidden,
//		},
//	}
//
//	for _, tc := range testCases {
//		t.Run(tc.name, func(t *testing.T) {
//			logger, err := zap.NewDevelopment()
//			if err != nil {
//				t.Fatalf("failed to create logger: %v", err)
//			}
//			store := mocks.NewStore(t)
//			auth := mocks.NewAuth(t)
//			h := group.NewHandler(logger, validator.New(), problem.New(), store, auth)
//
//			if tc.setupMocks != nil {
//				tc.setupMocks(store, auth)
//			}
//
//			r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/groups/%s/archive", groupID.String()), nil)
//			r.SetPathValue("group_id", groupID.String())
//			r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, tc.user))
//			w := httptest.NewRecorder()
//
//			h.ArchiveHandler(w, r)
//
//			assert.Equal(t, tc.wantStatus, w.Code)
//		})
//	}
//}
//
//func TestHandler_UnarchiveHandler(t *testing.T) {
//	groupID := uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")
//
//	testCases := []struct {
//		name       string
//		user       jwt.User
//		setupMocks func(*mocks.Store, *mocks.Auth)
//		wantStatus int
//	}{
//		{
//			name: "Should unarchive group for admin",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e9"),
//				RoleName: pgtype.Text{String: "admin", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store, auth *mocks.Auth) {
//				store.On("GetUserGroupRole", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e9"), groupID).Return(
//					group.GroupRole{},
//					databaseutil.WrapDBErrorWithKeyValue(pgx.ErrNoRows, "membership", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", groupID.String(), "a9e0fd99-10de-4ad1-b519-e8430ed089e9"), zap.NewExample(), "get membership"),
//				)
//				store.On("Unarchive", mock.Anything, mock.Anything).Return(group.Group{
//					Title:       "Test Group",
//					Description: pgtype.Text{String: "Test Description", Valid: true},
//				}, nil)
//			},
//			wantStatus: http.StatusOK,
//		},
//		{
//			name: "Should unarchive group for group owner",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e3"),
//				RoleName: pgtype.Text{String: "organizer", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store, auth *mocks.Auth) {
//				auth.On("GetUserGroupAccessLevel", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e3"), groupID).Return(
//					string(group.AccessLevelOwner), nil)
//				store.On("GetUserGroupRole", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e3"), groupID).Return(
//					group.GroupRole{
//						ID:          uuid.MustParse(string(group.RoleOwner)),
//						RoleName:        pgtype.Text{String: "group_owner", Valid: true},
//						AccessLevel: string(group.AccessLevelOwner),
//					},
//					nil)
//				store.On("Unarchive", mock.Anything, mock.Anything).Return(group.Group{
//					Title:       "Test Group",
//					Description: pgtype.Text{String: "Test Description", Valid: true},
//				}, nil)
//			},
//			wantStatus: http.StatusOK,
//		},
//		{
//			name: "Should not unarchive group for organizer not in this group",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e5"),
//				RoleName: pgtype.Text{String: "user", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store, auth *mocks.Auth) {
//				auth.On("GetUserGroupAccessLevel", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e5"), groupID).Return(
//					"", databaseutil.WrapDBErrorWithKeyValue(pgx.ErrNoRows, "membership", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", "a9e0fd99-10de-4ad1-b519-e8430ed089e5", groupID.String()), zap.NewExample(), "get membership"))
//			},
//			wantStatus: http.StatusNotFound,
//		},
//		{
//			name: "Should not unarchive group for group-admin",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e7"),
//				RoleName: pgtype.Text{String: "user", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store, auth *mocks.Auth) {
//				auth.On("GetUserGroupAccessLevel", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e7"), groupID).Return(
//					string(group.AccessLevelAdmin), nil)
//			},
//			wantStatus: http.StatusForbidden,
//		},
//		{
//			name: "Should not unarchive group for user",
//			user: jwt.User{
//				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e2"),
//				RoleName: pgtype.Text{String: "user", Valid: true},
//			},
//			setupMocks: func(store *mocks.Store, auth *mocks.Auth) {
//				auth.On("GetUserGroupAccessLevel", mock.Anything, uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e2"), groupID).Return(
//					string(group.AccessLevelUser), nil)
//			},
//			wantStatus: http.StatusForbidden,
//		},
//	}
//
//	for _, tc := range testCases {
//		t.Run(tc.name, func(t *testing.T) {
//			logger, err := zap.NewDevelopment()
//			if err != nil {
//				t.Fatalf("failed to create logger: %v", err)
//			}
//			store := mocks.NewStore(t)
//			auth := mocks.NewAuth(t)
//			h := group.NewHandler(logger, validator.New(), problem.New(), store, auth)
//
//			if tc.setupMocks != nil {
//				tc.setupMocks(store, auth)
//			}
//
//			r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/groups/%s/unarchive", groupID.String()), nil)
//			r.SetPathValue("group_id", groupID.String())
//			r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, tc.user))
//			w := httptest.NewRecorder()
//
//			h.UnarchiveHandler(w, r)
//
//			assert.Equal(t, tc.wantStatus, w.Code)
//		})
//	}
//}
