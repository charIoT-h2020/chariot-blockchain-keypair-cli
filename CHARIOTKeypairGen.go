package main

import (
  "fmt"
  "crypto/ecdsa"
  "crypto/sha256"
  "crypto/elliptic"
  "crypto/rand"
  "encoding/base64"
  "encoding/json"
  "os"
  "reflect"
  "math/big"
  "bufio"
)

// Wrapper for panic call on error
func check(e error) {
    if e != nil {
        // errorMessage := e.Error()
        panic(e)
    }
}

/**
 * Program for generating a CHARIOT compliant ECDSA keypair.
 * Inputs:
 * - (Optional) A text string to sign and verify, ensuring the keypair works correctly
 * Outputs:
 * - A .chrt file containing the CHARIOT Public & Private keys
 */
func main() {

    // Initialization of ECDSA & Program Variables
    randomGen := rand.Reader
    curve := elliptic.P256()
    filename := "keypair.chrt"
    privFile := "keypair.chrt"
    var sigTest string
    var genSig string
    var verJSON string

    // Check arguments
    for i := range os.Args {
        // Print help if the argument is detected
        if os.Args[i] == "-h" || os.Args[i] == "--help" {
            // Prints help & waits until the Enter Key is pressed
            fmt.Println("\nCHARIOT Keypair Generation Manual")
            fmt.Println("\n\n  Description:")
            fmt.Println("\n\n    This program is designed to create a P256 ECDSA keypair complian")
            fmt.Println("\n    t with the CHARIOT blockchain networks. The generated keypair wi")
            fmt.Println("\n    ll be saved to a text file for ease of access. This tool can also")
            fmt.Println("\n    be utilized to sign blockchain actions for the blockchain PKI.")
            fmt.Println("\n  Inputs:")
            fmt.Println("\n    --help: Prints this log. Shorthand: -h")
            fmt.Println("\n    --output arg: Specifies the filename of the output. Shorthand: -o arg")
            fmt.Println("\n    --test arg: Specifies a string to be used when conducting the signature verification test. Shorthand: -t arg")
            fmt.Println("\n    --input arg: Specifies the filename of the input for signing/verifying. Shorthand: -i arg")
            fmt.Println("\n    --sign arg: Specifies the public address of the sensor to sign. Shorthand: -s arg")
            fmt.Println("\n    --verify arg: Specifies the signature to verify in stringified JSON format with R & S keys. Requires --admin-address & --blockchain-action. Shorthand: -v arg")
            fmt.Println("\n    --admin-address arg: Specifies the address to verify the signature with. Required by --verify. Shorthand: -a arg")
            fmt.Println("\n    --blockchain-action arg: Specifies the blockchain action to verify the signature with. Required by --verify. Shorthand: -A arg")
            fmt.Println("\n\n  Outputs: A file containing the Private & Public Keys Base64 Encoded. Default: keypair.chrt")
            fmt.Println("\n\nPress Enter to exit...")
            fmt.Scanln(&sigTest)
            os.Exit(0)
        }
        // Ensure out-of-bounds check for malformed input
        if i == (len(os.Args) - 1) {
            break
        }
        // Set output file name & signature test name perspectively
        if os.Args[i] == "-o" || os.Args[i] == "--output" {
            filename = os.Args[i+1]
        } else if os.Args[i] == "-t" || os.Args[i] == "--test" || os.Args[i] == "-a" || os.Args[i] == "--admin-address" {
            sigTest = os.Args[i+1]
        } else if os.Args[i] == "-A" || os.Args[i] == "--blockchain-action" {
            privFile = os.Args[i+1]
        } else if os.Args[i] == "-i" || os.Args[i] == "--input" {
            privFile = os.Args[i+1]
        } else if os.Args[i] == "-s" || os.Args[i] == "--sign" {
            genSig = os.Args[i+1]
        } else if os.Args[i] == "-v" || os.Args[i] == "--verify" {
            verJSON = os.Args[i+1]
        }
    }

    // If it is a request for a signature, do not generate new keypair
    if genSig == "" && verJSON == "" {
      // Generation of a Private Key
      priv, err := ecdsa.GenerateKey(curve, randomGen)
      check(err)
      fmt.Printf("Private Key (Number): %s\n", priv.D.String())
      privEncoded := base64.StdEncoding.EncodeToString(priv.D.Bytes())
      fmt.Printf("Private Key (Base64): %s\n", privEncoded)

      // Verification that encoding was conducted correctly
      decodedPriv, err := base64.StdEncoding.DecodeString(privEncoded)
      check(err)
      if priv.D != priv.D.SetBytes(decodedPriv) {
          panic("Decoded value mis-match, exiting...")
      }

      // Derivation of Public Key w/ Type Assertion
      pub := priv.Public().(*ecdsa.PublicKey)
      fmt.Printf("Public Key X Coordinate: " + pub.X.String() + "\n")
      fmt.Printf("Public Key Y Coordinate: " + pub.Y.String() + "\n")

      // Digestion of Public Key to a SHA256 Hash
      digester := sha256.New()
      digester.Write(pub.X.Bytes())
      digester.Write(pub.Y.Bytes())
      pubDigest := digester.Sum(nil)
      fmt.Printf("Public Key SHA256 Digest (Base16): %X\n", pubDigest)
      pubEncoded := base64.StdEncoding.EncodeToString(pubDigest)
      fmt.Printf("Public Key SHA256 Digest (Base64): %s\n", pubEncoded)

      // Base64 Encoded Key Creation
      pubOne := base64.StdEncoding.EncodeToString(pub.X.Bytes())
      pubTwo := base64.StdEncoding.EncodeToString(pub.Y.Bytes())
      pubEncoded = base64.StdEncoding.EncodeToString([]byte(pubOne+pubTwo))
      fmt.Printf("Public Key Double Encoded (Base64): %s\n", pubEncoded)

      // Check that encoding was done correctly (Ref to signature generation for process)
      fullSlice, err := base64.StdEncoding.DecodeString(pubEncoded)
      check(err)

      tempSlice := fullSlice[0:44]
      firstSlice := tempSlice[:]

      tempSlice = fullSlice[44:88]
      secondSlice := tempSlice[:]

      decodedFirst, err := base64.StdEncoding.DecodeString(string(firstSlice))
      check(err)

      decodedSecond, err := base64.StdEncoding.DecodeString(string(secondSlice))
      check(err)

      newX := new(big.Int)
      newY := new(big.Int)

      decodedPub := &ecdsa.PublicKey{
        Curve: elliptic.P256(),
        X: newX.SetBytes(decodedFirst),
        Y: newY.SetBytes(decodedSecond)}

      if !reflect.DeepEqual(pub, decodedPub) {
          panic("Encoding was done incorrectly. Aborting execution.")
      } else {
          fmt.Printf("Public Key recreation was successful\n")
      }

      // Export keypair to the .chrt file format
      fmt.Printf("Saving generated keypair to %s\n", filename)
      file, err := os.Create(filename)
      check(err)
      defer file.Close()
      _, err = file.WriteString("-----BEGIN CHARIOT PRIVATE KEY-----\n")
      check(err)
      _, err = file.WriteString(privEncoded + "\n")
      check(err)
      _, err = file.WriteString("------END CHARIOT PRIVATE KEY------\n")
      check(err)
      _, err = file.WriteString("-----BEGIN CHARIOT PUBLIC KEY-----\n")
      check(err)
      _, err = file.WriteString(pubEncoded + "\n")
      check(err)
      _, err = file.WriteString("------END CHARIOT PUBLIC KEY------\n")
      check(err)
      fmt.Printf("Saved successfully!\n")

      // Conduct signature verification test if parameter is provided
      if sigTest != "" {
          hash := sha256.Sum256([]byte(sigTest))
          hexHash := hash[:]
          r, s, _ := ecdsa.Sign(randomGen, priv, hexHash)
          if ecdsa.Verify(pub, hexHash, r, s) {
              fmt.Printf("Signature creation & verification for blockchain action %s was conducted Succesfully\n", sigTest)
          } else {
              fmt.Printf("Signature creation & verification for blockchain action %s failed\n", sigTest)
          }
      }
    // Generate & Save Signature for chaincode invocation
    } else if verJSON == "" {
      // Read Private Key to sign with from file
      keyFile, err := os.Open(privFile)
      check(err)
      defer keyFile.Close()
      fileReader := bufio.NewReader(keyFile)

      // Skip first line
      _, _, err = fileReader.ReadLine()
      check(err)

      // Read Private Key
      line, _, err := fileReader.ReadLine()
      check(err)

      // Set it as variable for struct initialization
      newD := new(big.Int)
      tempBytes, err := base64.StdEncoding.DecodeString(string(line));
      check(err)
      newD = newD.SetBytes(tempBytes)

      // Skip next two lines
      _, _, err = fileReader.ReadLine()
      check(err)
      _, _, err = fileReader.ReadLine()
      check(err)

      // Read Pubic Key
      line, _, err = fileReader.ReadLine()
      check(err)

      // Decode First Layer
      fullSlice, err := base64.StdEncoding.DecodeString(string(line))
      check(err)

      // Split Layer into two 44 byte halves
      tempSlice := fullSlice[0:44]
      firstSlice := tempSlice[:]

      tempSlice = fullSlice[44:88]
      secondSlice := tempSlice[:]

      // Decode the Base64 encoded halves
      decodedFirst, err := base64.StdEncoding.DecodeString(string(firstSlice))
      check(err)

      decodedSecond, err := base64.StdEncoding.DecodeString(string(secondSlice))
      check(err)

      // Set them as variables for Struct initialization
      newX := new(big.Int)
      newY := new(big.Int)
      newX = newX.SetBytes(decodedFirst)
      newY = newY.SetBytes(decodedSecond)

      decodedPub := &ecdsa.PublicKey{Curve:elliptic.P256(), X:newX, Y:newY}
      decodedPriv := &ecdsa.PrivateKey{PublicKey:*decodedPub,D:newD}

      // Convert & Generate Signature
      hexHash := []byte(genSig)
      r, s, _ := ecdsa.Sign(randomGen, decodedPriv, hexHash)

      // Ensure proper signature generation
      if ecdsa.Verify(decodedPub, hexHash, r, s) {
          fmt.Printf("Signature creation & verification for blockchain action %s was conducted Succesfully\n", genSig)
      } else {
          fmt.Printf("Signature creation & verification for blockchain action %s failed\n", genSig)
      }

      // Encode signature values
      encodedR := base64.StdEncoding.EncodeToString(r.Bytes())
      encodedS := base64.StdEncoding.EncodeToString(s.Bytes())

      // Export encoded values to the .chrt file format
      filename := "signature.chrt"
      fmt.Printf("Saving generated signature to %s\n", filename)
      f, err := os.Create(filename)
      check(err)
      defer f.Close()
      _, err = f.WriteString("-----BEGIN CHARIOT R SIGNATURE-----\n")
      check(err)
      _, err = f.WriteString(encodedR + "\n")
      check(err)
      _, err = f.WriteString("------END CHARIOT R SIGNATURE------\n")
      check(err)
      _, err = f.WriteString("-----BEGIN CHARIOT S SIGNATURE-----\n")
      check(err)
      _, err = f.WriteString(encodedS + "\n")
      check(err)
      _, err = f.WriteString("------END CHARIOT S SIGNATURE------\n")
      check(err)
      fmt.Printf("Saved successfully!\n")
    } else {
      // Decode First Layer
      fullSlice, err := base64.StdEncoding.DecodeString(sigTest)
      check(err)

      // Split Layer into two 44 byte halves
      tempSlice := fullSlice[0:44]
      firstSlice := tempSlice[:]

      tempSlice = fullSlice[44:88]
      secondSlice := tempSlice[:]

      // Decode the Base64 encoded halves
      decodedFirst, err := base64.StdEncoding.DecodeString(string(firstSlice))
      check(err)

      decodedSecond, err := base64.StdEncoding.DecodeString(string(secondSlice))
      check(err)

      // Set them as variables for Struct initialization
      newX := new(big.Int)
      newY := new(big.Int)
      newX = newX.SetBytes(decodedFirst)
      newY = newY.SetBytes(decodedSecond)

      decodedPub := &ecdsa.PublicKey{Curve:elliptic.P256(), X:newX, Y:newY}

      // Convert item signed to raw bytes
      hexHash := []byte(privFile)

      type Signature struct {
        R string
        S string
      }

      var sig Signature
      json.Unmarshal([]byte(verJSON), &sig)

      // Decode R
      decodedR, err := base64.StdEncoding.DecodeString(sig.R)
      check(err)

      // Decode S
      decodedS, err := base64.StdEncoding.DecodeString(sig.S)
      check(err)

      r := new(big.Int)
      s := new(big.Int)
      r = r.SetBytes(decodedR)
      s = s.SetBytes(decodedS)

      // Verify signature
      if ecdsa.Verify(decodedPub, hexHash, r, s) {
          fmt.Printf("Signature verification for %s was conducted succesfully\n", privFile)
      } else {
          fmt.Printf("Signature verification for %s failed\n", privFile)
      }
    }

    // Waits until the Enter Key is pressed
    fmt.Println("Press Enter to exit...")
    fmt.Scanln(&sigTest)
}
