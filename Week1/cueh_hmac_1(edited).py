hmac_blocksize=16
def strToNum(inp):
    """Takes a sequence of bytes (KEY)and makes a number (HASH)"""
    out=0
    print("Converting string("+inp+") to a number...")
    for i in inp:
        out=out<<8
        out^=ord(i)
        print (out)
    return out
#-------------------------------------------------------------------------------------------------------------------------------------
def numToStr(inp):
    """Take a number and make ITS sequence of bytes INTO a string"""
    out=""
    print("++++++++++++++++++numToStr(key)++++++++++++++++++")

    print("Converting encoded key("+str(inp)+") to a string...")
    print("{:#018b}".format(inp)+ " = "+str(inp))
    print("{:#018b}".format(255)+ " = "+str(255)+" (mask)")

    while inp!=0:
        out=chr(inp & 255)+out #255 ACTS AS A BINARY MASK FOR THE FIRST 8 DIGITS TO BE CONVERTED TO A UNICODE CHARACTER
        print("{:#018b}".format(inp & 255)+" = "+out)
        inp=inp>>8 #SHIFTS THE ENTIRE BINARY TO REMOVE THE BITS THAT HAVE ALREADY BEEN CONVERTED TO A NUMBER
    return out
#--------------------------------------------------------------------------------------------------------------------------------
def cueh_hash_1(inp):
    """ CUEH Hash Function v 1.0 
    Returns 16 bit hash of any string input or stringable input
    """
    global hmac
    if hmac=="k":
        print("================cueh_hash_1(Key)==================")
    elif hmac =="km":
        print("=============cueh_hash_1(Key + Mssg)==============")


    inp=str(inp) #Make sure we have a string
    if len(inp)%2!=0:
        inp+=" " #Pad it if we need to
    ShiftAcc=0 #Our accumulator
    XorAcc=0
    count=0
    S=[0,0,0,0,0,0,0]
    for pos in range(0,len(inp),2): #Now in twos...
        i=inp[pos]
        print("       "+i+" =         "+"{:#010b}".format(ord(i))+"    "+str(ord(i)))
        j=inp[pos+1]
        print("       "+j+" = "+"{:#018b}".format(ord(j)<<8)+"    "+str(ord(j)))
        print ("Encoding/XOR...",i,j)
        ShiftAcc=(ord(i))  #XOR first char onto lowest 8 bits
        ShiftAcc^=(ord(j)<<8)  #and second char onto highest 8 bits
        print("ShiftAcc = "+"{:#018b}".format(ShiftAcc)+"   "+str(ShiftAcc))
        XorAcc^=ShiftAcc
        print("  XorAcc = "+"{:#018b}".format(XorAcc)+"   "+str(XorAcc))

        ShiftAcc=0
    print("   "+str(inp)+"  = "+"{:#018b}".format(XorAcc)+"   "+str(XorAcc)+"\n")
    return XorAcc
#-----------------------------------------------------------------------------------------------------------------------------------
def cueh_hmac_1(key, message):
    """Outputs a hash-based digest of the message and secret key combo"""
    print("MACMACMACMACMACMACMACMACMACMACMACMACMACMACMACMACM")
    message=str(message)
    global hmac
    if len(key)>hmac_blocksize/8: #IF KEY LENGTH IS > THAN 2 CHARS(16-bits)
        hmac="k"
        key=numToStr(cueh_hash_1(key)) #Keys are shortened to a 16-BIT blocksized character
        
    while len(key)<hmac_blocksize/8:
        key+=" " #Keys are padded with spaces if they're too short
    hmac="km"
    a=cueh_hash_1(key+message)
    print ("Value of hashed(key+mssg)   =   " +"0x%x"%a) 
    return a
#------------------------------------------------------------------------------------------------------------------------------------  
if __name__=="__main__":
    hmac=0
    
    secretKey=input("Enter Secret Key: ")#This is known by both parties
    authedMessage=input("Enter Secret Message: ")
    
    out=cueh_hmac_1(secretKey,authedMessage)
    
    print ("%d|%s"%(out, authedMessage))

