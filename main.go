package main

// import (
// 	"encoding/json"
// 	"fmt"
// 	"strconv"

// 	"github.com/duo-labs/webauthn/webauthn"
// )

// type User struct {
// 	ID          uint
// 	DisplayName string
// 	Name        string
// 	Icon        string
// }

// func (user User) WebAuthnID() []byte {
// 	str := strconv.Itoa(int(user.ID))
// 	return []byte(str)
// }

// func (user User) WebAuthnName() string {
// 	return user.Name
// }

// func (user User) WebAuthnDisplayName() string {
// 	return user.DisplayName
// }

// func (user User) WebAuthnIcon() string {
// 	return user.Icon
// }

// func main() {
// 	config := webauthn.Config{
// 		RelyingPartyDisplayName: "https://foo.bar.com",
// 		RelyingPartyID:          "foobar",
// 		Timeout:                 60000,
// 	}
// 	wb, err := webauthn.New(&config)
// 	if err != nil {
// 		fmt.Println("Error!", err)
// 	}

// 	testUser := User{
// 		ID:          12345,
// 		DisplayName: "Gucci Mane",
// 		Name:        "GucciMane",
// 		Icon:        "g.png",
// 	}

// 	opts, err := wb.BeginRegistration(testUser)
// 	printJSON(opts)
// 	return
// }

// func printJSON(d interface{}) {
// 	dj, err := json.MarshalIndent(d, "", "  ")
// 	if err != nil {
// 		fmt.Println("error creating JSON: ", err)
// 	}
// 	fmt.Printf("%s", dj)
// }
