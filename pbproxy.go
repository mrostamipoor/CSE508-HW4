package main

import (
		"fmt"
		"flag"
		"log"
		//"time"
		"bufio"
		"os"
		"strings"
		"net"
		"bytes"
		"strconv"
		"io"
		"crypto/aes"
		"crypto/cipher"
		"crypto/rand"
		"golang.org/x/crypto/pbkdf2"
		"crypto/sha256"
)
var (
		destIP net.IP
		destPort int 
		listenport *string
		filename *string
		pass string
)

const (
		ChunkSize = 4096 * 4096
		tcp = "tcp"
		NonceSize=12
)

func main() {
		
		handleinputs ()
		if *listenport != "" {
			lport,err:=strconv.Atoi(*listenport)
			if err != nil {
				fmt.Println("The port number %i is incorrect!", destPort)
				log.Fatal(err)
			}else {
			handleServer(lport)
			}
		}else {
			handleClient (destIP,destPort)
		}

}
func handleinputs () {
		
		 listenport = flag.String("l", "", "The listen port for server")
		 filename = flag.String("p", "", "The ASCII text passphrase")
		 flag.Parse()
		//----------------------handling passphrase file-----------------------------
		
		if *filename != "" {
			file, err := os.Open(*filename)
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			i:=0
		for scanner.Scan() {
			if i > 0{
			fmt.Println("Incorrect password format!")
			os.Exit(1)	
			}
			pass=pass+scanner.Text()
			i=i+1			
		}
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		} 
		}else {
			log.Println("Please enter the name of the file which contains the ASCII text passphrase")
			os.Exit(1)
		}
	//---------------handling IP address and port number-----------------------------------------------------
		var err error
		var add []string
		if len(flag.Args()) > 0 {
		 addresses:=flag.Args()
		 tmps := strings.Join(addresses, " ")
		 add=strings.Fields(tmps)
		if len(add)== 2 {
			destIP = net.ParseIP(add[0])
			if destIP == nil {
				log.Println("Invalid IP address detect!")
				os.Exit(1)
			}
			destPort,err=strconv.Atoi(add[1])
			if err != nil {
				fmt.Println("The port number %i is incorrect!", destPort)
			   log.Fatal(err)
			}
			}else {
			   fmt.Println("Please enter valid destination IP and port which want to connect")
			   os.Exit(1)
			}
		}else {
			log.Println("Please enter destination IP and port which want to connect")
			os.Exit(1)
		}

}

func handleServer(lport int) {
		
	  
	  addr := fmt.Sprintf("%s:%d", "", lport)
	  listener, err := net.Listen("tcp", addr)

	  if err != nil {
		log.Printf("Can not connect to this address: %s", addr)
		os.Exit(1)
	  }
	  log.Printf("Listening for connections on %s \n", addr)

	  for {
		
		conn, err := listener.Accept()
		if err != nil {
		  log.Printf("Error accepting connection from client: %s", err)
		} else {
			log.Printf("A new connection has established :)\n")
			go handleRequest(conn)

		}
	  }
}
func handleRequest(conn net.Conn){
		salt:=make([]byte,16)
		_,err:=conn.Read(salt)
		if err != nil {
			log.Printf("wrong port number or destination address! Please try again with valid address :) \n")
			conn.Close()
			return
		}
		key:= pbkdf2.Key([]byte(pass), salt, 4096, 32, sha256.New)
		//log.Printf("key:%x\n",key)
		
		addr := fmt.Sprintf("%s:%d",destIP.String(),destPort)	
			
		sshc, err := net.Dial("tcp", addr)
		if err != nil {
			log.Printf("wrong port number or destination address! Please try again with valid address :) \n")
			conn.Close()
			return
			
		}

	   done := make(chan bool,2)
	   go conncopydec(conn, sshc,done,key)
	   go conncopyenc(sshc, conn,done,key)
	   <-done
	   <-done

	   defer sshc.Close()
	   defer conn.Close()
}

func ScanItems(data []byte, atEOF bool) (advance int, token []byte, err error) {
	
	if atEOF && len(data) == 0 {
        return 0, nil, nil
    }
    if atEOF {
	  return len(data),data , nil
    }

    if i := bytes.Index(data, []byte("m^-!")); i >= 0 {
		//log.Println("index ",i )
		tmp:=[]byte{'`','!'}
		data=append(tmp,data[0:i]...)
        return i + 4, data, nil
    }

    return 0, nil, nil
}
func conncopyenc(connsrc net.Conn,conndst net.Conn,done chan bool,key []byte) error{
		var err error
		reader := bufio.NewReader(connsrc)
		writer := bufio.NewWriter(conndst)	
		

		defer writer.Flush()
		chunk := make([]byte, ChunkSize)	
		
		for {		
			chunkSize, err := reader.Read(chunk)
			if err == io.EOF || chunkSize == 0 {
				done <- true
				break
			} else if err != nil {
				return fmt.Errorf("Failed to read a chunk: %v", err)
			} else if chunkSize > 0 {
				tmpdata,err:=encrypt(chunk[:chunkSize],key)
					if err != nil {
						log.Printf("Error during encryptionff! \n")
						conndst.Close()
						connsrc.Close()
						done <- true
						return  err
					}
					tmp:=[]byte("m^-!")
					tmpdata=append(tmpdata,tmp...)
					_, err = writer.Write(tmpdata)
					//log.Println("sends: ",len(tmpdata))
				   writer.Flush()
					if err != nil {
						return fmt.Errorf("Failed to write an encrypted data: %v", err)
					}				
			}
			
		
		}
		
		done <- true
		return err;
}
func conncopydec(connsrc net.Conn,conndst net.Conn,done chan bool,key []byte) error{

		var err error
		reader := bufio.NewReader(connsrc)
		writer := bufio.NewWriter(conndst)	
		defer writer.Flush()
		var remind []byte
		for {	
			chunk := make([]byte, ChunkSize)
			chunkSize, err := reader.Read(chunk)
			if err == io.EOF || chunkSize == 0 {
				done <- true
				break
			} else if err != nil {
				return fmt.Errorf("Failed to read a chunk: %v\n", err)
			} else if chunkSize > 0 {
				//log.Println("recs: ",chunkSize)
					if len(remind) >0 {
						
					   chunk=append(remind,chunk[0:chunkSize]...)
					   chunkSize=chunkSize+len(remind)
					   //log.Println("recsw: ",chunkSize)
					   remind=nil  
					}
					
					r := bytes.NewReader(chunk[0:chunkSize])
					scanner := bufio.NewScanner(r)
					scanner.Split(ScanItems)
					for scanner.Scan() {
						token:=scanner.Bytes()
						if len(token)>2{
							if string(token[0:2])=="`!"{
							tmpdata,err:=decrypt(token[2:],key)
							if err != nil {
								log.Printf("Error during decryption! \n")
								conndst.Close()
								connsrc.Close()
								done <- true
								return  err
								}
							_, err = writer.Write(tmpdata)
							writer.Flush()
							if err != nil {
								return fmt.Errorf("Failed to write encrypted data: %v", err)
							}
			
							}else {
								remind=token
							}
						}
					}	
			}
		
		}
		
		done <- true
		return err;
}

func handleClient(destIP net.IP,destPort int) error{
		//log.Println("123")
		addr := fmt.Sprintf("%s:%d",destIP.String(),destPort)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			log.Printf("You have enter a wrong address or port!\n")
			return err
		}
		salt,err:=GenerateNonce(16)
		if err != nil {
			log.Printf("can not generate a key!\n")
			conn.Close()
			return err
			
		}
		_, err=conn.Write(salt)
		if err != nil {
			log.Printf("Connect error!\n")
			return err
		}
		key:= pbkdf2.Key([]byte(pass), salt, 4096, 32, sha256.New)
		done := make(chan bool,2)
		go outputcopy(os.Stdin,conn,done,key)
		go inputcopy(os.Stdout,conn,done,key)
		<-done
		<-done
		defer conn.Close()
		return err
}

func outputcopy(stdin *os.File,conn net.Conn,done chan bool,key []byte) error{
		var err error
		reader := bufio.NewReader(stdin)
		writer := bufio.NewWriter(conn)	
		defer writer.Flush()
		chunk := make([]byte, ChunkSize)
		for {	
			
			chunkSize, err := reader.Read(chunk)
			if err == io.EOF || chunkSize == 0 {
				done <- true
				break
			} else if err != nil {
				return fmt.Errorf("Failed to read a chunk: %v", err)
			} else if chunkSize > 0 {
					tmpdata,err:=encrypt(chunk[:chunkSize],key)
					if err != nil {
						log.Printf("Error during encryption! \n")
						conn.Close()
						done <- true
						return  err
					}
					tmp:=[]byte("m^-!")
					tmpdata=append(tmpdata,tmp...)
					_, err = writer.Write(tmpdata)
					//log.Println("client send ",len(tmpdata))
				   writer.Flush()
					if err != nil {
						return fmt.Errorf("Failed to write an encrypted data: %v", err)
					}
			}
		}
		
		done <- true
		return err;
}
func inputcopy(stdout *os.File,conn net.Conn,done chan bool,key []byte) error{
		var err error
		reader1 := bufio.NewReader(conn)
		writer1 := bufio.NewWriter(stdout)	
		defer writer1.Flush()
		var remind []byte
		for {	
			chunk := make([]byte, ChunkSize)
			chunkSize, err := reader1.Read(chunk)
			if err == io.EOF || chunkSize == 0 {
				done <- true
				break
			} else if err != nil {
				return fmt.Errorf("Failed to read a chunk: %v\n", err)
			} else if chunkSize > 0 {
				//log.Println("before: ",chunkSize)
					if len(remind) > 0 {
					   chunk=append(remind,chunk[0:chunkSize]...)
					  chunkSize=chunkSize+len(remind)
					   remind=nil
					   
					}
					
					r := bytes.NewReader(chunk[0:chunkSize])
					scanner := bufio.NewScanner(r)
					scanner.Split(ScanItems)
					for scanner.Scan() {
						token:=scanner.Bytes()
						
						if len(token) > 2{
							if string(token[0:2])=="`!"{
							tmpdata,err:=decrypt(token[2:],key)
							
							if err != nil {
								log.Printf("Error during decryption in client! \n")
								log.Println("chunkSize: ",chunkSize)
								log.Println("mes: ",len(token))
								conn.Close()
								done <- true
								return  err
								}
							_, err = writer1.Write(tmpdata)
							//log.Println("after: ",len(tmpdata))
							writer1.Flush()
							if err != nil {
								return fmt.Errorf("Failed to write encrypted data: %v", err)
							}
			
							}else {
								remind=token
							}
						}
					}			
			}
			
		
		}
		
		done <- true
		return err
}

func encrypt(plaintext []byte,key []byte) (ciphertext []byte,err error){
	
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil,err
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil,err
		}
		nonce,err:=GenerateNonce(NonceSize)
		if err != nil {
			log.Printf("len %d\n",len(ciphertext))
			return nil,err
		}
		ciphertext = aesgcm.Seal(nil, nonce, plaintext, nil)
		output := make([]byte, NonceSize + len(ciphertext))
        copy(output[:NonceSize], nonce)
        copy(output[NonceSize:], ciphertext)
		return output,nil
}
	
func decrypt(ciphertext []byte,key []byte) (plaintext []byte,err error){
	
		if len(ciphertext) < NonceSize {
			return nil, fmt.Errorf("Ciphertext too short.")
		}
		
		nonce := ciphertext[:NonceSize]
		msg := ciphertext[NonceSize:]
		if len (msg)==0 {
			return nil, nil
			}
	
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil,err
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil,err
		}
		plaintext, err = aesgcm.Open(nil, nonce, msg, nil)
		
		if err != nil {
			//time.Sleep(20* time.Millisecond)
			plaintext, err = aesgcm.Open(nil, nonce, msg, nil)
			if err != nil {
				return nil,err
			}
		}
		//log.Printf("enc size after %d\n", len(msg))
		return plaintext,err
}

func GenerateNonce(lenght int) ([]byte, error) {
		var err error
		b := make([]byte, lenght)
		_, err=rand.Read(b)
		return b,err
}