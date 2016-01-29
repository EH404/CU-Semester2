hmac_blocksize=16
def numToStr(inp):
    out=""
    while inp!=0:
        out=chr(inp & 255)+out #255 ACTS AS A BINARY MASK (WITH THE 'AND' LOGIC OPERATOR)FOR THE FIRST 8 DIGITS TO BE CONVERTED TO A UNICODE CHARACTER
        inp=inp>>8 #SHIFTS THE ENTIRE BINARY TO REMOVE THE BITS THAT HAVE BEEN CONVERTED TO A NUMBER
    return out
#-----------------------------------------------------------------
def strToNum(inp):
    out=0
    for i in inp:
        out=out<<8
        out^=ord(i)
    return out
#-------------------------------------------------------------------
def cueh_hmac_1(key, message):
    message=str(message)
    global hmac
    if len(key)>hmac_blocksize/8: #IF KEY LENGTH IS > THAN 2 CHARS(16-bits)
        hmac="k"
        key=numToStr(cueh_hash_1(key)) #Keys are shortened to a 16-BIT blocksized character
    while len(key)<hmac_blocksize/8:
        key+=" " #Keys are padded with spaces if they're too short
    hmac="km"
    a=cueh_hash_1(key+message)
    return a
#-------------------------------------------------------------------
def crack_digest_1(digest, mssg):
    mssg=str(mssg) #Make sure we have a string
    if len(mssg)%2!=0:
        mssg+=" " #Pad it if we need to
    ShiftAcc=0 #Our accumulator
    XorAcc=int(digest)
    count=0
    for pos in range(0,len(mssg),2): #Now in twos...
        i=mssg[pos]
        j=mssg[pos+1]
        ShiftAcc=(ord(i)<<8)  #XOR first char onto highest 8 bits
        ShiftAcc^=(ord(j))  #and second char onto lowest 8 bits
        XorAcc^=ShiftAcc        
        ShiftAcc=0
    return XorAcc
#--------------------------------------------------------------------
def hmacCrack (digest,message):
    if len(message) % 2 != 0:
        message += " "
    digest=int(digest)
    message=message[::-1]
    keyHash=crack_digest_1(digest, message)
    key=numToStr(int(keyHash))
    key=key[::-1]
    keyInBinary="{:016b}".format(strToNum(key))

    print("The key is: '"+(key)+"'")
    print("With the binary values of: "+keyInBinary[0:8]+" & "+keyInBinary[8:16])    
    print("-----------------------------------------------")
#------------------------------------------------------------------
def main():
    global exitProg
    userDigest= input("Enter 'Q' to end program."+"\n\nEnter digest number: ")
    if len(userDigest)== int(2) and userDigest == "Q":
        exitProg = True
        return
    userMssg= input("Enter message: ")
    hmacCrack(userDigest,userMssg)
    
#------------------------------------------------------------------
if __name__=="__main__":
    exitProg=False
    while exitProg==False:
        main()


