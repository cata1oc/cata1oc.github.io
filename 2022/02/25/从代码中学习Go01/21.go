package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"sync"
)

type (
	ioc_detail struct {
		Host string `json":host"`
		Port string `json":port"`
		Path string `json":path"`
	}

	intelligence_info struct {
		Type             string     `json":type"`
		Alert            bool       `json":alert"`
		Status           string     `json":status"`
		Risk             string     `json":risk"`
		Confidence       string     `json":confidence"`
		Malicious_type   uint8      `json":malicious_type"`
		Malicious_family string     `json":malicious_family"`
		Campaign         string     `json":campaign"`
		Control_type     string     `json":control_type"`
		Hot              bool       `json":hot"`
		Protocol         string     `json":protocol"`
		First_seen       uint64     `json":first_seen"`
		Last_seen        uint64     `json":last_seen"`
		Ioc              string     `json":ioc"`
		Ioc_detail       ioc_detail `json":ioc_detail"`
		Tags             []string   `json":tags"`
	}
)

func fatal(e error) {
	if e != nil {
		panic(e)
	}
}

func initial_syncmap(fp_map sync.Map) (ret_map sync.Map) {
	for i := 0; i <= 255; i++ {
		key := strconv.Itoa(i)
		filename := "iocjsonQueryTable\\" + key + ".csv"
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

func read_and_write(fp_map sync.Map) {

	// read json content in memory
	file, err := os.Open("ioc.json")
	fatal(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		json_str := scanner.Text()
		json_bytes := []byte(json_str)
		data := intelligence_info{}
		err = json.Unmarshal(json_bytes, &data)
		fatal(err)

		// write content in csv file
		// 1.get respondent file
		str_hex_uid := data.Ioc[0:2]
		uid, err := hex.DecodeString(str_hex_uid)
		fatal(err)
		str_uid := strconv.Itoa(int(uid[0]))
		filename := str_uid
		f, _ := fp_map.Load(filename)
		f_elem := reflect.ValueOf(f).Elem()
		f_addr := f_elem.Addr().Interface().(*os.File)
		var fp *os.File
		fp = f_addr
		fp.Close()

		// 2.prepare data write in csv
		elements := make([]string, 16)
		elements[0] = data.Type
		if data.Alert {
			elements[1] = "true"
		} else {
			elements[1] = ""
		}

		// w := csv.NewWriter(fp)
		// w.Write(data)
		// w.Flush()

		// i++
		// if i%50000 == 0 {
		// 	fmt.Println("already checked: ", i)
		// }
		continue
	}
}

func main() {
	var fp_map sync.Map
	fp_map = initial_syncmap(fp_map)

	read_and_write(fp_map)

	free_syncmap(fp_map)
}
