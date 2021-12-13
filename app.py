from flask import Flask, redirect, url_for, request, render_template, flash
import mysql.connector as mysql
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
import datetime,hashlib,time,os
con = mysql.connect(user='root', password='anku', host='127.0.0.1', database='mailvelope')
print("Connection established with DB :" + str(con.is_connected()))
difficulty=1
chainheight=0
transactionpool=[]
tpool=[]
utxo=[]
usr="saa"

class Transactions:

    def __init__(self):
        self.hash=""
        self.outs={'value':0,'receiver':''}
        self.sign=""  #{amt signed with privatekey of sender }
        self.inpts=""

    def addTransaction(self,usr,receiname="T",receiamt="T"):

        query = """SELECT pub_key 
                    FROM users
                    WHERE U_name='""" + receiname + """';"""
        publickeyout = service_provider(query)[0][0]
        query = """SELECT pri_key 
                   FROM users
                   WHERE U_name='""" + usr + """';"""
        prikeyinp =service_provider(query)[0][0]
        query = """SELECT pub_key 
                   FROM users
                    WHERE U_name='""" + usr + """';"""
        pubkeyinp = service_provider(query)[0][0]



        # sign the message
        f = open(prikeyinp, 'rt')
        key = ECC.import_key(f.read())
        hash_obj = SHA256.new(bytes(str(receiamt),'utf-8'))
        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(hash_obj)

        ##Generating transaction
        f = open(pubkeyinp, 'rt')
        self.inpts=ECC.import_key(f.read())
        self.outs['value']=receiamt
        f = open(publickeyout, 'rt')
        self.outs['receiver']=ECC.import_key(f.read())
        self.sign=signature
        hashy=bytes(str(self.inpts)+str(self.outs['value'])+str(self.outs['receiver'])+str(self.sign),'utf-8')
        self.hash=SHA256.new(hashy)

class Block:

    def __init__(self):
        self.hash=""
        self.prev_hash=""
        self.height=0
        self.timestamp=""
        self.nonce=0
        self.merkle_root=[]

def service_provider(query):
    try:
        cursor = con.cursor()
        cursor.execute(query)
        records = cursor.fetchall()
        return records
    except Exception as ex:
        print(ex)


def nonce_calculator(block_data):
    nonce = -1
    block_hash = ""
    tic = time.perf_counter()
    print("Calculating Nonce...")
    while block_hash[:difficulty] != "0" * difficulty:
        nonce += 1
        mystr = block_data + str(nonce)
        result = hashlib.sha256(mystr.encode())
        block_hash = result.hexdigest()

    toc = time.perf_counter()
    print("____________________________________________________")
    print("Block hash:", block_hash)
    print("Nonce     :", nonce)
    print(f"Time required :{toc - tic:0.4f} seconds")
    print("____________________________________________________")

    return nonce,block_hash

def generateKeys(usr):
    # generate key pairs
    key = ECC.generate(curve='P-256')
    ## public key
    public_key_filename = os.path.join("C:/Users/Ankita/PycharmProjects/Swabhav/PublicKeyPool/",
                                       "pub_" + usr + ".pem")
    key.public_key()
    f = open(public_key_filename, 'wt')
    f.write(key.export_key(format='PEM'))
    f.close()
    ## private key
    private_key_filename = os.path.join("C:/Users/Ankita/PycharmProjects/Swabhav/PrivateKeys/",
                                        "pri_" + usr + ".pem")
    f = open(private_key_filename, 'wt')
    f.write(key.export_key(format='PEM'))
    f.close()

    print("private key:\n", key.export_key(format="PEM"))
    print("public key", key.public_key())

    return private_key_filename, public_key_filename

def mine(transind):
    global publicheaderblock,chainheight,utxo
    # Verify the signature
    transind=int(transind)
    receivedmessage = bytes(transactionpool[transind].outs['value'], 'utf-8')
    hash_obj = SHA256.new(receivedmessage)
    pub_key = transactionpool[transind].inpts
    verifier = DSS.new(pub_key, 'fips-186-3')
    # Verify the authenticity of the message
    try:
        verifier.verify(hash_obj, transactionpool[transind].sign)
        print("_____________________✔______________________")
        flash("✔ The transaction is authorized by the sender | ")
    except ValueError:
        flash("Error! Transaction is not authorized")
        return
    ##Add the transaction from pool
    genblock = Block()
    genblock.prev_hash = publicheaderblock
    chainheight += 1
    genblock.height = chainheight
    genblock.timestamp = datetime.datetime.now()
    valid = False
    for i in range(len(utxo)):
        if utxo[i][0] == tpool[transind][0]:
            if utxo[i][1] > tpool[transind][2]:
                # Add remaining coins to the senders address
                utxo.append([tpool[transind][0], utxo[i][1] - tpool[transind][2]])
                utxo.append([tpool[transind][1], tpool[transind][2]])
                transacoin = Transactions()
                transacoin.addTransaction(usr,usr, utxo[i][1] - tpool[transind][2])
                genblock.merkle_root.append(transacoin)
                utxo.remove(utxo[i])
                valid = True
                break
            elif utxo[i][1] == tpool[transind][2]:
                utxo.remove(utxo[i])
                valid = True
                break
    if valid == False:
        flash("ERROR! Insufficient coins")
        return


    genblock.merkle_root.append(transactionpool[transind])
    transactionpool.remove(transactionpool[transind])
    tpool.remove(tpool[transind])
    ## Acoins awarded to the miner
    gentrans = Transactions()
    gentrans.inpts = "Newly generated coins"
    gentrans.outs['value'] = 50
    f = open("C:/Users/Ankita/PycharmProjects/Swabhav/PublicKeyPool/pub_" + usr + ".pem", 'rt')
    gentrans.outs['receiver'] = ECC.import_key(f.read())
    gentrans.sign = "AcoinSign"
    mystr = str(gentrans.inpts) + str(gentrans.outs['value']) + str(gentrans.outs['receiver']) + str(
        gentrans.sign)
    result = hashlib.sha256(mystr.encode())
    gentrans.hash = result.hexdigest()
    genblock.merkle_root.append(gentrans)
    ############
    # NONCE
    ############
    block_contents = str(genblock.merkle_root) + str(genblock.prev_hash) + str(genblock.timestamp) + str(
        genblock.height)
    noncecal, blockhash = nonce_calculator(block_contents)
    genblock.nonce = noncecal
    genblock.hash = blockhash
    publicheaderblock = genblock
    flash("Successfully added a new Block!!")


##################FLASK APP#####################

app = Flask(__name__)
app.secret_key = "abc"

@app.route('/transaction',methods=['POST','GET'])
def transaction():

    global usr
    query = """SELECT U_name FROM users;"""
    networklist = service_provider(query)
    if request.method == 'POST':
        receiname = request.form['name']
        receiamt = request.form['amount']
        transacoin = Transactions()
        tpool.append([usr, receiname, int(receiamt)])
        transacoin.addTransaction(usr, receiname,receiamt)
        transactionpool.append(transacoin)
        flash("Transaction Added Succesfully!")

    return render_template('transaction.html',networklist=networklist)


@app.route('/mining', methods=['POST', 'GET'])
def mining():
    global utxo
    utxo=utxo
    transactions = []
    i = 0
    for e in transactionpool:
        tran = [i,e.hash,e.inpts,e.outs['receiver'],e.outs['value'],str(e.sign)[:30]]
        transactions.append(tran)
        i += 1
    if request.method == 'POST':
        transid = request.form.get('transid')
        mine(transid)
    return render_template('mining.html', transactions=transactions)

@app.route('/chain')
def chain():
    global utxo
    utxo=utxo
    blocks=[]
    headerblock = publicheaderblock
    while (True):
        blocky=[headerblock.hash,headerblock.prev_hash,headerblock.height,headerblock.timestamp,headerblock.nonce,headerblock.merkle_root]
        blcktrans=[]
        for hb in headerblock.merkle_root:
            trans=[hb.hash, hb.inpts,hb.outs['receiver'], hb.outs['value'],str(hb.sign)[:30]]
            blcktrans.append(trans)
        blocky.append(blcktrans)
        blocks.append(blocky)

        if headerblock.prev_hash == "00000":
            break
        else:
            headerblock = headerblock.prev_hash
    print(blocks)
    return render_template('chain.html',utxo=utxo,blocks=blocks)

@app.route('/menu',methods=['POST','GET'])
def menu():
    global usr
    if request.method == 'POST':
        if request.form.get('tran') == 'Add Transaction':
            return redirect(url_for('transaction'))

        elif request.form.get('mine') == 'Mine for Blocks':
            return redirect(url_for('mining'))

    return render_template('menu.html')

@app.route('/login',methods=['POST','GET'])
def login():
    global usr
    print("here",request.method)
    if request.method == 'POST':
        usr = request.form['username']
        paswd = request.form['password']
        print("Username -",usr,"Password -",paswd)
        query = """SELECT P_word 
                            FROM users
                            WHERE U_name='""" + usr + """';"""
        passfetched = service_provider(query)
        if passfetched == []:
            flash("User not found")
        elif paswd == passfetched[0][0]:
            flash("Authentication successful !")
            return redirect(url_for('menu'))
    return render_template('login.html')



@app.route('/signup',methods=['POST','GET'])
def signup():
    global usr
    if request.method == 'POST':
        usr=request.form.get('username')
        paswd = request.form.get('password')
        query = """SELECT U_name FROM users;"""
        listusers = service_provider(query)
        exist=False
        for luser in listusers:
            if luser[0] == usr:
                exist=True
                flash("Username already taken")
                break
        if exist==False:
            flash("Generating key pairs for you..")
            pripath, pubpath = generateKeys(usr)
            query = """INSERT INTO users (U_name,P_word,pub_key,pri_key) VALUES
                                                                        ('""" + usr + """','""" + paswd + """','""" + pubpath + """','""" + pripath + """');"""
            service_provider(query)
            flash("Successfully generated keys !")
            return redirect(url_for('menu'))
    return render_template('signup.html')


@app.route('/',methods=['POST','GET'])
def index():
    if request.method == 'POST':
        if request.form.get('login') == 'Login':
            return redirect(url_for('login'))
        elif request.form.get('sign') == 'Sign Up':
            return redirect(url_for('signup'))
        elif request.form.get('view')=="View Chain":
            return redirect(url_for('chain'))
    return render_template('index.html')




############################################################################


if __name__ == "__main__":
    print("Welcome to Blockchain")
    # Genesis Block
    chainheight = 0
    gentrans = Transactions()
    gentrans.inpts = "Newly generated coins"
    gentrans.outs['value'] = 50
    f = open("C:/Users/Ankita/PycharmProjects/Swabhav/PublicKeyPool/pub_saa.pem", 'rt')
    gentrans.outs['receiver'] = ECC.import_key(f.read())
    gentrans.sign = "AcoinSign"
    hashy = bytes( str(gentrans.inpts) + str(gentrans.outs['value']) + str(gentrans.outs['receiver']) + str(gentrans.sign), 'utf-8')
    gentrans.hash = SHA256.new(hashy)
    transactionpool.append(gentrans)
    utxo.append(["saa", 50])
    genblock = Block()
    genblock.prev_hash = "00000"
    genblock.height = chainheight
    genblock.timestamp = datetime.datetime.now()
    genblock.nonce = 100
    hashy = bytes( str(genblock.merkle_root) + str(genblock.prev_hash) + str(genblock.nonce) + str(genblock.timestamp) + str(
            genblock.height), 'utf-8')
    genblock.hash = SHA256.new(hashy)
    genblock.merkle_root.append(transactionpool[0])
    transactionpool.remove(transactionpool[0])
    publicheaderblock = genblock
    app.run()