package main

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"os"

	"reflect"
	"strconv"

	"strings"
	"sync"
)

func fatal(e error) {
	if e != nil {
		panic(e)
	}
}

func calculateHash(fp_map sync.Map, domain string) {

	salt := "75s#$1cf!5|6cdsD9c&D43&c^^_3D4444f##1dD|Fs*R#d5"
	element := make([]string, 2)

	hash_str := []byte(domain + salt)
	hash := sha256.New()
	hash.Write(hash_str)
	hash_bytes := hash.Sum(nil)
	hash_code := strings.ToUpper(hex.EncodeToString(hash_bytes))
	str_hex_uid := hash_code[0:2]
	uid, err := hex.DecodeString(str_hex_uid)
	fatal(err)
	// fmt.Println(uid[0], "   ", hash_code, "   ", domain)

	// Writing Data in .csv
	str_uid := strconv.Itoa(int(uid[0]))
	filename := str_uid
	f, _ := fp_map.Load(filename)
	// fmt.Println(f)
	f_elem := reflect.ValueOf(f).Elem()
	f_addr := f_elem.Addr().Interface().(*os.File)
	var fp *os.File
	fp = f_addr

	element[0] = hash_code
	element[1] = domain
	w := csv.NewWriter(fp)
	w.Write(element)
	w.Flush()
	// fmt.Println(element)

}

func readCsv(fp_map sync.Map) {
	for i := 1574; i <= 3145; i++ {
		prefix := strconv.Itoa(i)
		filename := "origin_csv\\" + prefix + "_full.csv"
		f, err := os.Open(filename)
		if err == nil {
			fmt.Println(filename)
			r := csv.NewReader(f)
			for {
				row, err := r.Read()
				if err != nil {
					break
				}
				domain := row[0]
				// fmt.Println(domain)
				calculateHash(fp_map, domain)
			}
			f.Close()
		}
	}
}

func main() {

	var fp_map sync.Map

	// Store file pointer in sync map
	for i := 0; i <= 255; i++ {
		key := strconv.Itoa(i)
		filename := key + ".csv"
		f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE, 0666)
		fatal(err)
		fp_map.Store(key, f)
	}

	readCsv(fp_map)

	for i := 0; i <= 255; i++ {
		key := strconv.Itoa(i)
		f, ok := fp_map.Load(key)
		if ok == false {
			fmt.Println("Nothing Find!")
		}

		f_elem := reflect.ValueOf(f).Elem()
		f_addr := f_elem.Addr().Interface().(*os.File)
		// fmt.Println(f_addr, reflect.TypeOf(f_addr))
		var fp *os.File
		fp = f_addr
		fp.Close()
	}
	fmt.Println("Over!")
}
