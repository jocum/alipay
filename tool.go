package alipay

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

/*
	部分小工具存放该文件
*/

/*
	@Description 	常有几种类型的interface 转string
	@Params
		i	interface{}
	@Return 	string
	@Author	cwy
*/
func InterfaceToString(i interface{}) (s string, err error) {
	switch i.(type) {
	case string:
		s = i.(string)
		return
	case int:
		s = strconv.Itoa(i.(int))
		return
	case int64:
		s = strconv.FormatInt(i.(int64), 10)
		return
	case float64:
		s = strconv.FormatFloat(i.(float64), 'f', -1, 64)
		return
	case float32:
		s = strconv.FormatFloat(float64(i.(float32)), 'f', -1, 64)
		return
	default:
		err = errors.New("not format intface type")
		return
	}
}

/*
	@Descritpion 	对提供的源进行 rsa 加密
	@Params
		src 	[]byte 	需要加密的源
		privateKey 	*rsa.PrivateKey 	加密用的rsa 私钥
		hash 	crypto.Hash 	采用的加密方式
	@Return
		res 	[]byte 	加密后的密文
		err		error
	@Author
*/
func RSASign(src []byte, privateKey *rsa.PrivateKey, hash crypto.Hash) ([]byte, error) {
	h := hash.New()
	h.Write(src)
	hashed := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashed)
}

/*
	@Description  对提供的源数据  和 sign  进行验签
	@Params
		src 	[]byte 	数据源
		sign 	[]byte  	需要校验的sign
		publicKey 	*rsa.PublicKey 	 验签公钥
		hash 	crypto.Hash
	@Return
		err 	error
	@Author	cwy
*/
func RSAVerifySign(src, sign []byte, publicKey *rsa.PublicKey, hash crypto.Hash) error {
	var h = hash.New()
	h.Write(src)
	var hashed = h.Sum(nil)
	return rsa.VerifyPKCS1v15(publicKey, hash, hashed, sign)
}

/*
	@Description 	格式化证书
*/
func FormatKey(raw, prefix, suffix string, lineCount int) []byte {
	if raw == "" {
		return nil
	}
	raw = strings.Replace(raw, prefix, "", 1)
	raw = strings.Replace(raw, suffix, "", 1)
	raw = strings.Replace(raw, " ", "", -1)
	raw = strings.Replace(raw, "\n", "", -1)
	raw = strings.Replace(raw, "\r", "", -1)
	raw = strings.Replace(raw, "\t", "", -1)

	var sl = len(raw)
	var c = sl / lineCount
	if sl%lineCount > 0 {
		c = c + 1
	}

	var buf bytes.Buffer
	buf.WriteString(prefix + "\n")
	for i := 0; i < c; i++ {
		var b = i * lineCount
		var e = b + lineCount
		if e > sl {
			buf.WriteString(raw[b:])
		} else {
			buf.WriteString(raw[b:e])
		}
		buf.WriteString("\n")
	}
	buf.WriteString(suffix)
	return buf.Bytes()
}

/*
	简单的添加 key 的前后缀
*/
func PreFixKey(key, prefix, suffix string) string {
	if key == "" {
		return ""
	}
	key = strings.Replace(key, prefix, "", 1)
	key = strings.Replace(key, suffix, "", 1)
	key = strings.Replace(key, " ", "", -1)
	key = strings.Replace(key, "\n", "", -1)
	key = strings.Replace(key, "\r", "", -1)
	key = strings.Replace(key, "\t", "", -1)
	var buf bytes.Buffer
	buf.WriteString(prefix + "\n")
	buf.WriteString(key)
	buf.WriteString("\n")
	buf.WriteString(suffix)
	return string(buf.Bytes())
}

/*
	@Description 	go的interface{} 其实有内置的结构  将map 结构 转化成对应的结构体
	@Params
		source 	interface{}		需要转化的数据
		response 	interface{}	 转化后的数据
	@Return
		err		error
	@Author	cwy
*/
func Conversion(source interface{}, response interface{}) error {
	// 先将 source 转化json
	result, err := json.Marshal(source)
	if err != nil {
		return err
	}
	return json.Unmarshal(result, response)
}
