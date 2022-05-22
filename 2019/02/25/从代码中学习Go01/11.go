package main

import (
	"crypto/hmac"
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

func calculate_hash(ip string) (ip_hash string) {

	key := "6LrLSQ!nm8Ft$&$!#4P65Y$5*LXn8Xw6oGE_gr!Hhc^@qGpF"
	keyb := []byte(key)
	ipb := []byte(ip)

	mac := hmac.New(sha256.New, keyb)
	mac.Write(ipb)
	msgmac := mac.Sum(nil)
	hash_code := strings.ToUpper(hex.EncodeToString(msgmac))
	// fmt.Printf(hash_code)
	return hash_code
}

func initial_syncmap(fp_map sync.Map) (ret_map sync.Map) {
	for i := 0; i <= 255; i++ {
		key := strconv.Itoa(i)
		filename := "iptab_hmac256\\" + key + ".csv"
		f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE, 0666)
		fatal(err)
		fp_map.Store(key, f)
	}
	return fp_map
}

func free_syncmap(fp_map sync.Map) {
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

func generate_and_writein(start_ip string, c chan int, fp_map sync.Map) {

	ip_addr := []string{"1", "0", "0", "0"}
	ip_addr[0] = start_ip
	// store elements writed in csvfile
	elements := make([]string, 2)

	for {
		num_3, _ := strconv.Atoi(ip_addr[3])
		num_2, _ := strconv.Atoi(ip_addr[2])
		num_1, _ := strconv.Atoi(ip_addr[1])

		if num_3 < 255 {
			num_3++
			ip_addr[3] = strconv.Itoa(num_3)
			ip_str := strings.Join(ip_addr, ".")
			ip_hash := calculate_hash(ip_str)

			str_hex_uid := ip_hash[0:2]
			uid, err := hex.DecodeString(str_hex_uid)
			fatal(err)
			fmt.Println(uid[0], "   ", ip_str, "   ", ip_hash)

			// Writing Data in .csv
			str_uid := strconv.Itoa(int(uid[0]))
			filename := str_uid
			f, _ := fp_map.Load(filename)
			// fmt.Println(f)
			f_elem := reflect.ValueOf(f).Elem()
			f_addr := f_elem.Addr().Interface().(*os.File)
			var fp *os.File
			fp = f_addr

			elements[0] = ip_str
			elements[1] = ip_hash
			w := csv.NewWriter(fp)
			w.Write(elements)
			w.Flush()
			continue

		} else if num_2 < 255 {
			ip_addr[3] = strconv.Itoa(0)
			num_2++
			ip_addr[2] = strconv.Itoa(num_2)
			continue

		} else if num_1 < 255 {
			ip_addr[2] = strconv.Itoa(0)
			num_1++
			ip_addr[1] = strconv.Itoa(num_1)
			continue

		} else if num_1 == 255 && num_2 == 255 && num_3 == 255 {
			break
		}
	}
}

func main() {

	var fp_map sync.Map
	fp_map = initial_syncmap(fp_map)

	// multi go routine generate ip & hash and write in csvfile
	c := make(chan int)
	for i := 1; i <= 255; i++ {
		if i == 10 || i == 127 || i == 256 {
			continue
		}
		start_ip := strconv.Itoa(i)
		go generate_and_writein(start_ip, c, fp_map)
	}
	wait := <-c
	fmt.Println(wait)

	free_syncmap(fp_map)
}
