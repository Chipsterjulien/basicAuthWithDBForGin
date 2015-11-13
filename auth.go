package basicAuthWithDBForGin

import (
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"encoding/base64"
)

const AuthUserKey = "user"

type (
	authPair struct {
		User  string `gorm:"column:identifiant"`
		Value string `gorm:"column:mot_de_passe"`
	}
	authPairs []authPair
)

func (a authPairs) processAccount() {
	for num, pair := range a {
		a[num].Value = authorizationHeader(pair.User, pair.Value)
	}
}

func (a authPairs) searchCredential(authValue string) (string, bool) {
	if len(authValue) == 0 {
		return "", false
	}
	for _, pair := range a {
		if pair.Value == authValue {
			return pair.User, true
		}
	}
	return "", false
}

func authorizationHeader(user, password string) string {
	base := user + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(base))
}

func BasicAuthWithDBForRealm(db *gorm.DB, nameOfTable string) gin.HandlerFunc {
	realm := "Basic realm=Authorization Required"

	return func (c *gin.Context) {
		pairs := authPairs{}
		db.Table(nameOfTable).Select("identifiant, mot_de_passe").Find(&pairs)
		pairs.processAccount()

		user, found := pairs.searchCredential(c.Request.Header.Get("Authorization"))
		if !found {
			// Credentials doesn't match, we return 401 and abort handlers chain.
			c.Header("WWW-Authenticate", realm)
			c.AbortWithStatus(401)	
		} else {
			c.Set(AuthUserKey, user)
		}
	}
}

func BasicAuthWithDB(db *gorm.DB, nameOfTable string) gin.HandlerFunc {
	return BasicAuthWithDBForRealm(db, nameOfTable)
}