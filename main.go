// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// 2fa is a two-factor authentication agent.
//
// Usage:
//
//	2fa -add [-7] [-8] [-hotp] name
//	2fa -list
//	2fa [-clip] name
//
// “2fa -add name” adds a new key to the 2fa keychain with the given name.
// It prints a prompt to standard error and reads a two-factor key from standard input.
// Two-factor keys are short case-insensitive strings of letters A-Z and digits 2-7.
//
// By default the new key generates time-based (TOTP) authentication codes;
// the -hotp flag makes the new key generate counter-based (HOTP) codes instead.
//
// By default the new key generates 6-digit codes; the -7 and -8 flags select
// 7- and 8-digit codes instead.
//
// “2fa -list” lists the names of all the keys in the keychain.
//
// “2fa name” prints a two-factor authentication code from the key with the
// given name. If “-clip” is specified, 2fa also copies the code to the system
// clipboard.
//
// With no arguments, 2fa prints two-factor authentication codes from all
// known time-based keys.
//
// The default time-based authentication codes are derived from a hash of
// the key and the current time, so it is important that the system clock have
// at least one-minute accuracy.
//
// The keychain is stored unencrypted in the text file $HOME/.2fa.
//
// Example
//
// During GitHub 2FA setup, at the “Scan this barcode with your app” step,
// click the “enter this text code instead” link. A window pops up showing
// “your two-factor secret,” a short string of letters and digits.
//
// Add it to 2fa under the name github, typing the secret at the prompt:
//
//	$ 2fa -add github
//	2fa key for github: nzxxiidbebvwk6jb
//	$
//
// Then whenever GitHub prompts for a 2FA code, run 2fa to obtain one:
//
//	$ 2fa github
//	268346
//	$
//
// Or to type less:
//
//	$ 2fa
//	268346	github
//	$
//
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
)

// usage message
const usageMessage = `
usage: 2fa <command> [options] keyname
	-help : print this help message and exit
	-add : add a key
		-7 : generate 7-digit code
		-8 : generate 8-digit code
		-hotp : add hotp 2fa
	-list : print all keys
	-clip : copy the code to clipboard

	-viewRecover: view recovery code for a key
`

type KeyType int

const (
	// TOTP is a time-based key.
	TOTP KeyType = iota
	// HOTP is a counter-based key.
	HOTP
)

type KeyChain struct {
	File string
	Keys map[string]*Key
}

type Key struct {
	Name        string
	Raw         []byte   // raw key bytes
	Key         []byte   // key from the user
	Digits      int      // 6 or 7 or 8
	RecoverCode []string // recover code given by the user
	Counter     uint64   // counter for HTOP
	KeyType     KeyType  // TOTP or HOTP
}

var (
	flagAdd  = flag.Bool("add", false, "add a key")
	flagList = flag.Bool("list", false, "list keys")
	flagHotp = flag.Bool("hotp", false, "add key as HOTP (counter-based) key")
	flag7    = flag.Bool("7", false, "generate 7-digit code")
	flag8    = flag.Bool("8", false, "generate 8-digit code")
	flagClip = flag.Bool("clip", false, "copy code to the clipboard")

	flagViewRecoverCode = flag.Bool("viewRecover", false, "view recover code for a key")

	flagSetSaveFile = flag.Bool("setSaveFile", false, "set save file location")
)

func main() {
	log.SetPrefix("2fa: ")
	log.SetFlags(0)
	flag.Usage = usage
	flag.Parse()

	// read key chain
	k, err := readKeyChain(filepath.Join(os.Getenv("HOME"), ".local/share/2fa"))
	if err != nil {
		log.Fatal(err)
	}

	if err := handle(k); err != nil {
		log.Fatal(err)
	}

	// save key chain
	if err := k.saveKeyChainFile(); err != nil {
		log.Fatal(err)
	}
}

func handle(k *KeyChain) error {
	if *flagList {
		if flag.NArg() != 0 {
			usage()
		}
		k.list()
		return nil
	}
	if flag.NArg() == 0 && !*flagAdd {
		if *flagClip {
			usage()
		}
		k.list()
		return nil
	}
	if flag.NArg() != 1 {
		usage()
	}
	name := flag.Arg(0)
	// trim name to avoid leading/trailing whitespace
	name = strings.TrimSpace(name)
	if *flagAdd {
		if *flagClip {
			usage()
		}
		err := k.add(name)
		if err != nil {
			return err
		}
		return nil
	}

	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, usageMessage)
	os.Exit(2)
}

// read key chain from file
func readKeyChain(file string) (*KeyChain, error) {
	c := &KeyChain{
		File: file,
		Keys: make(map[string]*Key),
	}

	data, err := ioutil.ReadFile(file)
	if os.IsNotExist(err) {
		// No key chain file yet. That's fine.
		return c, nil
	}
	if err != nil {
		return nil, err
	}

	// if the data is blank, return new blank key chain
	if len(data) == 0 {
		return c, nil
	}

	// read the data using json
	err = json.Unmarshal(data, &c)
	if err != nil {
		return nil, err
	}

	// if the file path stored in the key chain is different from the one we are using, read from the new file
	if c.File != file {
		return readKeyChain(c.File)
	}

	return c, nil
}

func (c *KeyChain) saveKeyChainFile() error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}

	err = os.MkdirAll(filepath.Dir(c.File), 0700)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(c.File, data, 0600)
}

// print name of all existing keys
func (c *KeyChain) list() {
	longest := 0
	var names []string
	for name := range c.Keys {
		names = append(names, name)
		if len(name) > longest {
			longest = len(name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Println(name + strings.Repeat(" ", longest-len(name)+2) + c.code(name)) // +2 for the tab
	}
}

// add a key
func (c *KeyChain) add(name string) error {
	if _, ok := c.Keys[name]; ok {
		return fmt.Errorf("key %q already exists", name)
	}

	// check size
	size := 6
	if *flag7 {
		size = 7
		if *flag8 {
			return fmt.Errorf("cannot specify both -7 and -8")
		}
	} else if *flag8 {
		size = 8
	}

	// ask for key
	fmt.Fprintf(os.Stdout, "2fa key for %s: ", name)
	text, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("error reading key: %v", err)
	}
	text = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, text)
	text += strings.Repeat("=", -len(text)&7) // pad to 8 bytes

	// test key valid
	raw, err := decodeKey(text)
	if err != nil {
		log.Fatalf("invalid key: %v", err)
	}

	// ask for recovery code
	fmt.Fprintf(os.Stdout, "recover code ( separated by space or , or ; or | ) for %s: ", name)
	recoverCodeText, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("error reading key: %v", err)
	}
	// match recover code by space or , or ; or |
	recoverCode := strings.FieldsFunc(recoverCodeText, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';' || r == '|' || r == '\t'
	})
	// delete empty entry of recover code
	for i := 0; i < len(recoverCode); i += 1 {
		if recoverCode[i] == "" {
			recoverCode = append(recoverCode[:i], recoverCode[i+1:]...)
			i -= 1
		}
	}

	var key *Key = &Key{
		Name:        name,
		Raw:         raw,
		Digits:      size,
		KeyType:     TOTP,
		Key:         []byte(text),
		Counter:     0,
		RecoverCode: recoverCode,
	}

	if *flagHotp {
		key.KeyType = HOTP
	}

	c.Keys[name] = key

	return nil
}

// return the real code for a key
func (c *KeyChain) code(name string) string {
	k, ok := c.Keys[name]
	if !ok {
		log.Fatalf("no such key %q", name)
	}
	var code int

	switch k.KeyType {
	case TOTP:
		code = totp(k.Raw, time.Now(), k.Digits)
	case HOTP:
		code = hotp(k.Raw, k.Counter, k.Digits)
		k.Counter++
	}

	return fmt.Sprintf("%0*d", k.Digits, code)
}

func decodeKey(key string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(strings.ToUpper(key))
}

func hotp(key []byte, counter uint64, digits int) int {
	h := hmac.New(sha1.New, key)
	binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	d := uint32(1)
	for i := 0; i < digits && i < 8; i++ {
		d *= 10
	}
	return int(v % d)
}

func totp(key []byte, t time.Time, digits int) int {
	return hotp(key, uint64(t.UnixNano())/30e9, digits)
}
