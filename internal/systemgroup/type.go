package systemgroup

import (
	"time"

	"github.com/google/uuid"
)

// Member is a Clustron user that Clustron added to a system group.
type Member struct {
	UserID   uuid.UUID
	Email    string
	FullName string
	AddedAt  time.Time
}
