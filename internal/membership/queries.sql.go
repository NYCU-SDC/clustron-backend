// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: queries.sql

package membership

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

const addOrUpdate = `-- name: AddOrUpdate :one
INSERT INTO memberships (group_id, user_id, role_id)
VALUES ($1, $2, $3)
ON CONFLICT (user_id, group_id) DO UPDATE SET role_id = EXCLUDED.role_id
RETURNING user_id, group_id, role_id, created_at, updated_at
`

type AddOrUpdateParams struct {
	GroupID uuid.UUID
	UserID  uuid.UUID
	RoleID  uuid.UUID
}

func (q *Queries) AddOrUpdate(ctx context.Context, arg AddOrUpdateParams) (Membership, error) {
	row := q.db.QueryRow(ctx, addOrUpdate, arg.GroupID, arg.UserID, arg.RoleID)
	var i Membership
	err := row.Scan(
		&i.UserID,
		&i.GroupID,
		&i.RoleID,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const addOrUpdatePending = `-- name: AddOrUpdatePending :one
INSERT INTO pending_memberships (user_identifier, group_id, role_id)
VALUES ($1, $2, $3)
ON CONFLICT (user_identifier, group_id) DO UPDATE SET role_id = EXCLUDED.role_id
RETURNING id, user_identifier, group_id, role_id, created_at, updated_at
`

type AddOrUpdatePendingParams struct {
	UserIdentifier string
	GroupID        uuid.UUID
	RoleID         uuid.UUID
}

func (q *Queries) AddOrUpdatePending(ctx context.Context, arg AddOrUpdatePendingParams) (PendingMembership, error) {
	row := q.db.QueryRow(ctx, addOrUpdatePending, arg.UserIdentifier, arg.GroupID, arg.RoleID)
	var i PendingMembership
	err := row.Scan(
		&i.ID,
		&i.UserIdentifier,
		&i.GroupID,
		&i.RoleID,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const countByGroupID = `-- name: CountByGroupID :one
SELECT COUNT(*) FROM memberships
WHERE group_id = $1
`

func (q *Queries) CountByGroupID(ctx context.Context, groupID uuid.UUID) (int64, error) {
	row := q.db.QueryRow(ctx, countByGroupID, groupID)
	var count int64
	err := row.Scan(&count)
	return count, err
}

const delete = `-- name: Delete :exec
DELETE FROM memberships
WHERE group_id = $1 AND user_id = $2
`

type DeleteParams struct {
	GroupID uuid.UUID
	UserID  uuid.UUID
}

func (q *Queries) Delete(ctx context.Context, arg DeleteParams) error {
	_, err := q.db.Exec(ctx, delete, arg.GroupID, arg.UserID)
	return err
}

const existsByID = `-- name: ExistsByID :one
SELECT EXISTS (
    SELECT 1
    FROM memberships
    WHERE group_id = $1 AND user_id = $2
) AS exists
`

type ExistsByIDParams struct {
	GroupID uuid.UUID
	UserID  uuid.UUID
}

func (q *Queries) ExistsByID(ctx context.Context, arg ExistsByIDParams) (bool, error) {
	row := q.db.QueryRow(ctx, existsByID, arg.GroupID, arg.UserID)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const existsByIdentifier = `-- name: ExistsByIdentifier :one
SELECT EXISTS (
    SELECT 1
    FROM memberships AS m
    JOIN users AS u ON u.id = m.user_id
    WHERE group_id = $1 AND (u.student_id = $2 OR u.email = $2)
)
`

type ExistsByIdentifierParams struct {
	GroupID   uuid.UUID
	StudentID pgtype.Text
}

func (q *Queries) ExistsByIdentifier(ctx context.Context, arg ExistsByIdentifierParams) (bool, error) {
	row := q.db.QueryRow(ctx, existsByIdentifier, arg.GroupID, arg.StudentID)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const existsPendingByIdentifier = `-- name: ExistsPendingByIdentifier :one
SELECT EXISTS (
    SELECT 1
    FROM pending_memberships
    WHERE group_id = $1 AND user_identifier = $2
) AS exists
`

type ExistsPendingByIdentifierParams struct {
	GroupID        uuid.UUID
	UserIdentifier string
}

func (q *Queries) ExistsPendingByIdentifier(ctx context.Context, arg ExistsPendingByIdentifierParams) (bool, error) {
	row := q.db.QueryRow(ctx, existsPendingByIdentifier, arg.GroupID, arg.UserIdentifier)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const getMembershipByUser = `-- name: GetMembershipByUser :one
SELECT
    m.user_id,
    m.group_id,
    m.role_id,
    gr.role,
    gr.access_level
FROM
    memberships AS m
        JOIN
    group_role AS gr ON gr.id = m.role_id
WHERE
    user_id = $1 AND group_id = $2
`

type GetMembershipByUserParams struct {
	UserID  uuid.UUID
	GroupID uuid.UUID
}

type GetMembershipByUserRow struct {
	UserID      uuid.UUID
	GroupID     uuid.UUID
	RoleID      uuid.UUID
	Role        string
	AccessLevel string
}

func (q *Queries) GetMembershipByUser(ctx context.Context, arg GetMembershipByUserParams) (GetMembershipByUserRow, error) {
	row := q.db.QueryRow(ctx, getMembershipByUser, arg.UserID, arg.GroupID)
	var i GetMembershipByUserRow
	err := row.Scan(
		&i.UserID,
		&i.GroupID,
		&i.RoleID,
		&i.Role,
		&i.AccessLevel,
	)
	return i, err
}

const getPendingByIdentifier = `-- name: GetPendingByIdentifier :one
SELECT id, user_identifier, group_id, role_id, created_at, updated_at
FROM pending_memberships
WHERE group_id = $1 AND user_identifier = $2
`

type GetPendingByIdentifierParams struct {
	GroupID        uuid.UUID
	UserIdentifier string
}

func (q *Queries) GetPendingByIdentifier(ctx context.Context, arg GetPendingByIdentifierParams) (PendingMembership, error) {
	row := q.db.QueryRow(ctx, getPendingByIdentifier, arg.GroupID, arg.UserIdentifier)
	var i PendingMembership
	err := row.Scan(
		&i.ID,
		&i.UserIdentifier,
		&i.GroupID,
		&i.RoleID,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const listGroupMembersAscPaged = `-- name: ListGroupMembersAscPaged :many
SELECT
    m.group_id,
    m.user_id,
    s.username,
    u.email,
    u.student_id,
    m.role_id,
    gr.role,
    gr.access_level
FROM memberships AS m
JOIN group_role AS gr ON gr.id = m.role_id
JOIN users AS u ON u.id = m.user_id
JOIN settings AS s ON s.user_id = u.id
WHERE group_id = $1
ORDER BY $2::text ASC
LIMIT $4 OFFSET $3
`

type ListGroupMembersAscPagedParams struct {
	GroupID uuid.UUID
	Sortby  string
	Skip    int32
	Size    int32
}

type ListGroupMembersAscPagedRow struct {
	GroupID     uuid.UUID
	UserID      uuid.UUID
	Username    pgtype.Text
	Email       string
	StudentID   pgtype.Text
	RoleID      uuid.UUID
	Role        string
	AccessLevel string
}

func (q *Queries) ListGroupMembersAscPaged(ctx context.Context, arg ListGroupMembersAscPagedParams) ([]ListGroupMembersAscPagedRow, error) {
	rows, err := q.db.Query(ctx, listGroupMembersAscPaged,
		arg.GroupID,
		arg.Sortby,
		arg.Skip,
		arg.Size,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ListGroupMembersAscPagedRow
	for rows.Next() {
		var i ListGroupMembersAscPagedRow
		if err := rows.Scan(
			&i.GroupID,
			&i.UserID,
			&i.Username,
			&i.Email,
			&i.StudentID,
			&i.RoleID,
			&i.Role,
			&i.AccessLevel,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const listGroupMembersDescPaged = `-- name: ListGroupMembersDescPaged :many
SELECT
    m.group_id,
    m.user_id,
    s.username,
    u.email,
    u.student_id,
    m.role_id,
    gr.role,
    gr.access_level
FROM memberships AS m
JOIN group_role AS gr ON gr.id = m.role_id
JOIN users AS u ON u.id = m.user_id
JOIN settings AS s ON s.user_id = u.id
WHERE group_id = $1
ORDER BY $2::text DESC
LIMIT $4 OFFSET $3
`

type ListGroupMembersDescPagedParams struct {
	GroupID uuid.UUID
	Sortby  string
	Skip    int32
	Size    int32
}

type ListGroupMembersDescPagedRow struct {
	GroupID     uuid.UUID
	UserID      uuid.UUID
	Username    pgtype.Text
	Email       string
	StudentID   pgtype.Text
	RoleID      uuid.UUID
	Role        string
	AccessLevel string
}

func (q *Queries) ListGroupMembersDescPaged(ctx context.Context, arg ListGroupMembersDescPagedParams) ([]ListGroupMembersDescPagedRow, error) {
	rows, err := q.db.Query(ctx, listGroupMembersDescPaged,
		arg.GroupID,
		arg.Sortby,
		arg.Skip,
		arg.Size,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ListGroupMembersDescPagedRow
	for rows.Next() {
		var i ListGroupMembersDescPagedRow
		if err := rows.Scan(
			&i.GroupID,
			&i.UserID,
			&i.Username,
			&i.Email,
			&i.StudentID,
			&i.RoleID,
			&i.Role,
			&i.AccessLevel,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const updateMembershipRole = `-- name: UpdateMembershipRole :one
UPDATE memberships
SET role_id = $1
WHERE group_id = $2 AND user_id = $3
RETURNING user_id, group_id, role_id, created_at, updated_at
`

type UpdateMembershipRoleParams struct {
	RoleID  uuid.UUID
	GroupID uuid.UUID
	UserID  uuid.UUID
}

func (q *Queries) UpdateMembershipRole(ctx context.Context, arg UpdateMembershipRoleParams) (Membership, error) {
	row := q.db.QueryRow(ctx, updateMembershipRole, arg.RoleID, arg.GroupID, arg.UserID)
	var i Membership
	err := row.Scan(
		&i.UserID,
		&i.GroupID,
		&i.RoleID,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const updatePending = `-- name: UpdatePending :one
UPDATE pending_memberships
SET role_id = $1
WHERE group_id = $2 AND user_identifier = $3
RETURNING id, user_identifier, group_id, role_id, created_at, updated_at
`

type UpdatePendingParams struct {
	RoleID         uuid.UUID
	GroupID        uuid.UUID
	UserIdentifier string
}

func (q *Queries) UpdatePending(ctx context.Context, arg UpdatePendingParams) (PendingMembership, error) {
	row := q.db.QueryRow(ctx, updatePending, arg.RoleID, arg.GroupID, arg.UserIdentifier)
	var i PendingMembership
	err := row.Scan(
		&i.ID,
		&i.UserIdentifier,
		&i.GroupID,
		&i.RoleID,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}
