package main

import (
	"github.com/mattermost/mattermost/server/public/model"
)

// api is a narrow interface over the Mattermost plugin API methods used by
// this plugin. It allows unit tests to inject a mock without a running
// Mattermost server.
type api interface {
	LoadPluginConfiguration(dest interface{}) error
	GetConfig() *model.Config
	LogInfo(message string, keyValuePairs ...interface{})
	LogWarn(message string, keyValuePairs ...interface{})
	LogError(message string, keyValuePairs ...interface{})
	GetUserByEmail(email string) (*model.User, *model.AppError)
	GetUserByUsername(username string) (*model.User, *model.AppError)
	CreateUser(user *model.User) (*model.User, *model.AppError)
	CreateSession(session *model.Session) (*model.Session, *model.AppError)
}
