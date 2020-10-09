import random
from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, SelectField
from passlib.hash import sha256_crypt
from functools import wraps
from flask_uploads import UploadSet, configure_uploads, IMAGES
import timeit
from flask_mail import Mail, Message
import os
from wtforms.fields.html5 import EmailField
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_wtf import RecaptchaField
import requests
import stripe


app = Flask(__name__)
app.secret_key = os.urandom(24)
mysql = MySQL()


#Payments configuration
pub_key = 'pk_test_qWd1krxg65UlYPKm2RZpvOqh000R1Zb1qr'
secret_key = 'sk_test_OgUzTBPd1RJydSF4TLkWlZ8A001cbWidEo'
stripe.api_key = secret_key

#Uploading configuration
app.config['UPLOADED_PHOTOS_DEST'] = 'static/image'
photos = UploadSet('photos', IMAGES)
configure_uploads(app, photos)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

##Database configuration
app.config['MYSQL_HOST'] = os.environ.get("db_host")
app.config['MYSQL_USER'] = os.environ.get("db_user")
app.config['MYSQL_PASSWORD'] = os.environ.get("db_pass")
app.config['MYSQL_DB'] = os.environ.get("db_name")
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'


#Mail server configuration
app.config['MAIL_SERVER']=os.environ.get("mail_server")
app.config['MAIL_PORT'] = os.environ.get("mail_port")
app.config['MAIL_USERNAME'] = os.environ.get("mail_username")
app.config['MAIL_PASSWORD'] = os.environ.get("mail_password")
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False


#Recaptcha configuration
app.config['RECAPTCHA_PUBLIC_KEY'] =os.environ.get("recaptcha_public")
app.config['RECAPTCHA_PRIVATE_KEY']=os.environ.get("recaptcha_private")
app.config['RECAPTCHA_ENABLED']= True

#SMS configuration
authorization=os.environ.get("sms_auth")

mail = Mail(app)
mysql.init_app(app)

def send_msg(email,title,message):
    msg = Message(title, sender='aicteprojectspec@gmail.com', recipients=[email])
    msg.body = message
    mail.send(msg)

def sendSMS(number,message):
    url = "https://www.fast2sms.com/dev/bulk"

    payload = f"sender_id=FSTSMS&message={message}&language=english&route=p&numbers={number}"
    headers = {
        'authorization': authorization,
        'Content-Type': "application/x-www-form-urlencoded",
        'Cache-Control': "no-cache",
    }

    response = requests.request("POST", url, data=payload, headers=headers)
    print(response.text)

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, *kwargs)
        else:
            return redirect(url_for('login'))

    return wrap


def not_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return redirect(url_for('index'))
        else:
            return f(*args, *kwargs)

    return wrap


def is_admin_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin_logged_in' in session:
            return f(*args, *kwargs)
        else:
            return redirect(url_for('admin_login'))

    return wrap


def not_admin_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin_logged_in' in session:
            return redirect(url_for('admin'))
        else:
            return f(*args, *kwargs)

    return wrap


def wrappers(func, *args, **kwargs):
    def wrapped():
        return func(*args, **kwargs)

    return wrapped


def content_based_filtering(product_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM products WHERE id=%s", (product_id,))  # getting id row
    data = cur.fetchone()  # get row info
    data_cat = data['category']  # get id category ex shirt

    category_matched = cur.execute("SELECT * FROM products WHERE category=%s", (data_cat,))  # get all shirt category

    cat_product = cur.fetchall()  # get all row
    cur.execute("SELECT * FROM product_level WHERE product_id=%s", (product_id,))  # id level info
    id_level = cur.fetchone()
    recommend_id = []
    cate_level = ['v_shape', 'polo', 'clean_text', 'design', 'leather', 'color', 'formal', 'converse', 'loafer', 'hook',
                  'chain']
    for product_f in cat_product:
        cur.execute("SELECT * FROM product_level WHERE product_id=%s", (product_f['id'],))
        f_level = cur.fetchone()
        match_score = 0
        if f_level['product_id'] != int(product_id):
            for cat_level in cate_level:
                if f_level[cat_level] == id_level[cat_level]:
                    match_score += 1
            if match_score == 11:
                recommend_id.append(f_level['product_id'])

    if recommend_id:
        cur = mysql.connection.cursor()
        placeholders = ','.join((str(n) for n in recommend_id))
        query = 'SELECT * FROM products WHERE id IN (%s)' % placeholders
        cur.execute(query)
        recommend_list = cur.fetchall()
        return recommend_list, recommend_id, category_matched, product_id
    else:
        return ''


@app.route('/')
def index():
    print(os.environ.get("db_host"))
    return render_template('home.html')

@app.route('/forgotpass',methods=['GET','POST'])

def forgotpass():
    if 'logged_in' in session:
        return render_template('home.html')
    if 'mobile' in request.form:
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE mobile=%s", [request.form.get('mobile')])
        if result > 0:
            session['mobile'] = request.form.get('mobile')
            session['code'] = str(random.randrange(100000, 999999))

            sendSMS(session['mobile'], session['code'])
        else:
            flash('Number does not exist', 'danger')
            return render_template('forgotpass.html')
    if 'newpass' in request.form:
        password = sha256_crypt.encrypt(str(request.form.get('newpass')))
        curs = mysql.connection.cursor()
        curs.execute("UPDATE users SET password=%s WHERE mobile=%s", (password,session['mobile']))
        session.clear()
        flash('Password sucessfully changed', 'success')
        return redirect(url_for('login'))

    if 'otp' in request.args:
        code=request.args['otp']
        if 'code' in session:
            if code==session['code']:

                session['reset']=True
            else:

                flash('Invalid OTP, try again', 'danger')
        else:
            flash('please try again','danger')
            return render_template('forgotpass.html')
    return render_template('forgotpass.html')



@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=864000)
    except SignatureExpired:
        return '<h1>The token is expired!</h1>'
    curs = mysql.connection.cursor()
    curs.execute("UPDATE users SET activation=%s WHERE email=%s", ('yes', email))
    flash('Account activated!You can login now.', 'success')
    return redirect(url_for('login'))

@app.route('/smg')
def smg():
    send_msg('princeptl123456@gmail.com','hello','world')
    return "sent"



@app.route('/workshop',methods=['GET', 'POST'])
def workshop():
    form = OrderForm(request.form)
    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM workshops")
    workshops=cur.fetchall()

    if request.method == 'POST' and form.validate():

        name = form.name.data
        mobile = form.mobile_num.data
        quantity = form.quantity.data
        wid = request.args['join']
        # Create Cursor
        curs = mysql.connection.cursor()
        curs2 = mysql.connection.cursor()
        if 'uid' in session:
            uid = session['uid']
            curs.execute("INSERT INTO participants(uid, wid, uname, mobile,quantity) "
                         "VALUES(%s, %s, %s, %s, %s)",
                         (uid, wid, name, mobile, quantity))

        else:
            flash('Login first!', 'danger')
            return redirect(url_for('login'))

        # Commit cursor
        mysql.connection.commit()
        # Close Connection
        cur.close()

        flash('Sucessfully Joined', 'success')
        return render_template('workshop.html',workshops=workshops)
    if 'view' in request.args:
        q = request.args['view']
        workshop_id = q
        curso = mysql.connection.cursor()
        curso.execute("SELECT * FROM workshops WHERE id=%s", (q,))
        workshops1 = curso.fetchall()
        print(workshops1)
        return render_template('view_workshop.html', workshops=workshops1)
    elif 'join' in request.args:
        workshop_id = request.args['join']
        curso = mysql.connection.cursor()
        curso.execute("SELECT * FROM workshops WHERE id=%s", (workshop_id,))
        workshops1 = curso.fetchall()

        return render_template('join_workshop.html',workshops=workshops1,form=form)
    return render_template('workshop.html', workshops=workshops,form=form)

@app.route('/shop')
def shop():
    form = OrderForm(request.form)
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM products")
    products = cur.fetchall()
    cur.close()
    if 'product_id' in request.args:
        q = request.args['product_id']
        curso = mysql.connection.cursor()
        curso.execute("SELECT * FROM products WHERE id=%s", (q,))
        products = curso.fetchall()
        return render_template('view_product.html', products=products)

    return render_template('shop.html', products=products)


class LoginForm(Form):  # Create Login Form
   # username = StringField('', [validators.length(min=1)],render_kw={'autofocus': True, 'placeholder': 'Username'})
   # password = PasswordField('', [validators.length(min=3)],render_kw={'placeholder': 'Password'})
    recaptcha = RecaptchaField()


# User Login
@app.route('/login', methods=['GET', 'POST'])
@not_logged_in
def login():
    form = LoginForm(request.form)

    if request.method == 'POST' and form.validate():
        # GEt user form
        username = request.form.get('username')
        # password_candidate = request.form['password']
        password_candidate = request.form.get('pass')
        #

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username=%s", [username])

        if result > 0:
            # Get stored value
            data = cur.fetchone()
            password = data['password']
            uid = data['id']
            name = data['name']

            # Compare password
            if sha256_crypt.verify(password_candidate, password):
                # passed
                if(data['activation']=='yes'):
                    session['logged_in'] = True
                    session['uid'] = uid
                    session['s_name'] = name
                    x = '1'
                    cur.execute("UPDATE users SET online=%s WHERE id=%s", (x, uid))
                    return redirect(url_for('index'))
                else:
                    flash('Account not activated', 'danger')
                    return render_template('login.html', form=form)

            else:
                flash('Incorrect password', 'danger')
                return render_template('login.html', form=form)

        else:
            flash('Username not found', 'danger')
            # Close connection
            cur.close()
            return render_template('login.html', form=form)

    return render_template('login.html', form=form)


@app.route('/out')
def logout():
    if 'uid' in session:
        # Create cursor
        cur = mysql.connection.cursor()
        uid = session['uid']
        x = '0'
        cur.execute("UPDATE users SET online=%s WHERE id=%s", (x, uid))
        session.clear()
        flash('You are logged out', 'success')
        return redirect(url_for('index'))
    return redirect(url_for('login'))


class RegisterForm(Form):
    #name = StringField('', [validators.length(min=3, max=50)],
    #                   render_kw={'autofocus': True, 'placeholder': 'Full Name'})
    #username = StringField('', [validators.length(min=3, max=25)], render_kw={'placeholder': 'Username'})
    #email = EmailField('', [validators.DataRequired(), validators.Email(), validators.length(min=4, max=25)],
    #                   render_kw={'placeholder': 'Email'})
    #password = PasswordField('', [validators.length(min=3)],
     #                        render_kw={'placeholder': 'Password'})
    #mobile = StringField('', [validators.length(min=11, max=15)], render_kw={'placeholder': 'Mobile'})
    recaptcha=RecaptchaField()



@app.route('/register', methods=['GET', 'POST'])
@not_logged_in
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = request.form.get('name')
        email = request.form.get('email')
        username = request.form.get('username')
        password = sha256_crypt.encrypt(str(request.form.get('pass')))
        mobile = request.form.get('mobile')
        curs = mysql.connection.cursor()
        if curs.execute("SELECT * FROM users WHERE email=%s", [email]) >= 1:
            flash('Email Already exist', 'danger')
            return redirect(url_for('register'))
        elif curs.execute("SELECT * FROM users WHERE username=%s", [username]) >= 1:
            flash('Username Already exist', 'danger')
            return redirect(url_for('register'))
        elif curs.execute("SELECT * FROM users WHERE mobile=%s", [mobile]) >= 1:
            flash('Mobile Already exist', 'danger')
            return redirect(url_for('register'))
        # Create Cursor
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(name, email, username, password, mobile,activation) VALUES(%s, %s, %s, %s, %s,%s)",
                    (name, email, username, password, mobile,'No'))
        token = s.dumps(email, salt='email-confirm')

        msg = Message('Confirm Email', sender='projecthandblooom@gmail.com', recipients=[email])

        link = url_for('confirm_email', token=token, _external=True)

        msg.body = 'Your Activation link is : {}'.format(link)

        mail.send(msg)
        # Commit cursor
        mysql.connection.commit()

        # Close Connection
        cur.close()

        flash('Check your email for confirmation Link.', 'success')
        return redirect(url_for('index'))
    return render_template('register.html', form=form)


class MessageForm(Form):  # Create Message Form
    body = StringField('', [validators.length(min=1)], render_kw={'autofocus': True})


@app.route('/chatting/<string:id>', methods=['GET', 'POST'])
def chatting(id):
    if 'uid' in session:
        form = MessageForm(request.form)
        # Create cursor
        cur = mysql.connection.cursor()

        # lid name
        get_result = cur.execute("SELECT * FROM users WHERE id=%s", [id])
        l_data = cur.fetchone()
        if get_result > 0:
            session['name'] = l_data['name']
            uid = session['uid']
            session['lid'] = id

            if request.method == 'POST' and form.validate():
                txt_body = form.body.data
                # Create cursor
                cur = mysql.connection.cursor()
                cur.execute("INSERT INTO messages(body, msg_by, msg_to) VALUES(%s, %s, %s)",
                            (txt_body, id, uid))
                # Commit cursor
                mysql.connection.commit()

            # Get users
            cur.execute("SELECT * FROM users")
            users = cur.fetchall()

            # Close Connection
            cur.close()
            return render_template('chat_room.html', users=users, form=form)
        else:
            flash('No permission!', 'danger')
            return redirect(url_for('index'))
    else:
        return redirect(url_for('login'))


@app.route('/chats', methods=['GET', 'POST'])
def chats():
    if 'lid' in session:
        id = session['lid']
        uid = session['uid']
        # Create cursor
        cur = mysql.connection.cursor()
        # Get message
        cur.execute("SELECT * FROM messages WHERE (msg_by=%s AND msg_to=%s) OR (msg_by=%s AND msg_to=%s) "
                    "ORDER BY id ASC", (id, uid, uid, id))
        chats = cur.fetchall()
        # Close Connection
        cur.close()
        return render_template('chats.html', chats=chats, )
    return redirect(url_for('login'))


class OrderForm(Form):  # Create Order Form
    name = StringField('', [validators.length(min=1), validators.DataRequired()],
                       render_kw={'autofocus': True, 'placeholder': 'Full Name'})
    mobile_num = StringField('', [validators.length(min=1), validators.DataRequired()],
                             render_kw={'autofocus': True, 'placeholder': 'Mobile'})
    quantity = SelectField('', [validators.DataRequired()],
                           choices=[('1', '1'), ('2', '2'), ('3', '3'), ('4', '4'), ('5', '5')])
    order_place = StringField('', [validators.length(min=1), validators.DataRequired()],
                              render_kw={'placeholder': 'Order Place'})



@app.route('/admin_login', methods=['GET', 'POST'])
@not_admin_logged_in
def admin_login():
    if request.method == 'POST':
        # GEt user form
        username = request.form['email']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM admin WHERE email=%s", [username])

        if result > 0:
            # Get stored value
            data = cur.fetchone()
            password = data['password']
            uid = data['id']
            name = data['firstName']

            # Compare password
            if  password_candidate==password:
                # passed
                session['admin_logged_in'] = True
                session['admin_uid'] = uid
                session['admin_name'] = name

                return redirect(url_for('admin'))

            else:
                flash('Incorrect password', 'danger')
                return render_template('pages/login.html')

        else:
            flash('Username not found', 'danger')
            # Close connection
            cur.close()
            return render_template('pages/login.html')
    return render_template('pages/login.html')



@app.route('/admin_out')
def admin_logout():
    if 'admin_logged_in' in session:
        session.clear()
        return redirect(url_for('admin_login'))
    return redirect(url_for('admin'))

@app.route('/all_workshops')
@is_admin_logged_in
def all_workshops():
    curso = mysql.connection.cursor()
    workshop_rows = curso.execute("SELECT * FROM workshops")
    result = curso.fetchall()
    participant_rows = curso.execute("SELECT * FROM participants")
    users_rows = curso.execute("SELECT * FROM users")
    product_rows = curso.execute("SELECT * FROM products")
    order_rows = curso.execute("SELECT * FROM orders")

    return render_template('pages/all_workshops.html', result=result,workshop_rows=workshop_rows,participant_rows=participant_rows, product_rows=product_rows, order_rows=order_rows,
                           users_rows=users_rows)

@app.route('/admin')
@is_admin_logged_in
def admin():
    curso = mysql.connection.cursor()
    product_rows = curso.execute("SELECT * FROM products")
    result = curso.fetchall()
    order_rows = curso.execute("SELECT * FROM orders")
    workshop_rows = curso.execute("SELECT * FROM workshops")
    participant_rows = curso.execute("SELECT * FROM participants")
    users_rows = curso.execute("SELECT * FROM users")
    return render_template('pages/index.html', result=result,workshop_rows=workshop_rows,participant_rows=participant_rows, product_rows=product_rows, order_rows=order_rows,
                           users_rows=users_rows)

@app.route('/all_participant')
@is_admin_logged_in
def all_participant():
    curso = mysql.connection.cursor()

    participant_rows = curso.execute("SELECT * FROM participants")

    result = curso.fetchall()
    users_rows = curso.execute("SELECT * FROM users")
    product_rows = curso.execute("SELECT * FROM products")
    order_rows = curso.execute("SELECT * FROM orders")
    workshop_rows = curso.execute("SELECT * FROM workshops")
    return render_template('pages/all_participants.html', result=result,workshop_rows=workshop_rows,participant_rows=participant_rows, product_rows=product_rows, order_rows=order_rows,
                           users_rows=users_rows)


@app.route('/orders')
@is_admin_logged_in
def orders():
    curso = mysql.connection.cursor()
    order_rows = curso.execute("SELECT * FROM orders")
    result = curso.fetchall()
    workshop_rows = curso.execute("SELECT * FROM workshops")
    participant_rows = curso.execute("SELECT * FROM participants")
    users_rows = curso.execute("SELECT * FROM users")
    product_rows = curso.execute("SELECT * FROM products")
    return render_template('pages/all_orders.html', result=result,workshop_rows=workshop_rows,participant_rows=participant_rows, product_rows=product_rows, order_rows=order_rows,
                           users_rows=users_rows)


@app.route('/addToCart')
@is_logged_in
def addToCart():
    if 'productId' and 'quantity' in request.args:
        productId = request.args.get('productId')
        quantity = request.args.get('quantity')
        uid=session['uid']
        curso = mysql.connection.cursor()
        curso.execute("SELECT * FROM products WHERE id=%s", (productId,))
        price=curso.fetchall()
        total=price[0]['price']
        y=int(total)*int(quantity)

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO cart(userId,id,quantity,total)"
                     "VALUES(%s, %s, %s,%s)",
                     (uid,productId,quantity,y))
        mysql.connection.commit()
        cur.close()
    return ('', 204)



@app.route('/cart')
@is_logged_in
def cart():
    cur = mysql.connection.cursor()
    uid=session['uid']
    cur.execute("SELECT * FROM products ,cart WHERE products.id =cart.id AND cart.userid=%s", (uid,))
    items=cur.fetchall()
    total=0
    for x in range(len(items)):
        total=total+items[x]['total']
    return render_template('cart.html',items=items,total=total,pub_key=pub_key)


@app.route('/pay', methods=['POST'])
@is_logged_in
def pay():
    country = request.form.get('country')
    state = request.form.get('state')
    postcode = request.form.get('postcode')
    address = request.form.get('address')
    cur = mysql.connection.cursor()
    uid = session['uid']
    cur.execute("SELECT * FROM products ,cart WHERE products.id =cart.id AND cart.userid=%s", (uid,))
    items = cur.fetchall()
    total=0

    for x in range(len(items)):
        total = total + items[x]['total']
    total=total*100
    customer = stripe.Customer.create(email=request.form['stripeEmail'], source=request.form['stripeToken'])
    charge = stripe.Charge.create(
        customer=customer.id,
        amount=total,
        currency='inr',
        description='The Product'
    )
    result = cur.execute("SELECT * FROM cart WHERE userId=%s", [uid])
    #print(result)
    #print('test')
    if result > 0:
        #print('test')
        data = cur.fetchone()
        cid=data['cid']
        #print(uid, cid, request.form['stripeEmail'], address, country,state,postcode)
        cur.execute("INSERT INTO orders(uid,cid,email, address, country,state,postcode) "
                    "VALUES(%s, %s, %s, %s, %s, %s, %s)",
                    ([uid], [cid], request.form['stripeEmail'], address, country,state,postcode,))
    #print('test2')
    return redirect(url_for('thanks'))

@app.route('/thanks')
@is_logged_in
def thanks():
    return "<h1>Order success<h1>"

@app.route('/users')
@is_admin_logged_in
def users():
    curso = mysql.connection.cursor()

    users_rows = curso.execute("SELECT * FROM users")
    result = curso.fetchall()
    product_rows = curso.execute("SELECT * FROM products")
    order_rows = curso.execute("SELECT * FROM orders")
    workshop_rows = curso.execute("SELECT * FROM workshops")
    participant_rows = curso.execute("SELECT * FROM participants")
    return render_template('pages/all_users.html', result=result,workshop_rows=workshop_rows,participant_rows=participant_rows, product_rows=product_rows, order_rows=order_rows,
                           users_rows=users_rows)


@app.route('/admin_add_product', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_add_product():
    if request.method == 'POST':
        name = request.form.get('name')
        price = request.form['price']
        description = request.form['description']
        available = request.form['available']
        category = request.form['category']
        file = request.files['picture']
        if name and price and description and available and category and file:
            pic = file.filename
            photo = pic.replace("'", "")
            picture = photo.replace(" ", "_")
            if picture.lower().endswith(('.png', '.jpg', '.jpeg')):
                save_photo = photos.save(file, folder="product/"+category)
                if save_photo:
                    # Create Cursor
                    curs = mysql.connection.cursor()
                    curs.execute("INSERT INTO products(pName,price,description,item,pcode,available,category,picture)"
                                 "VALUES(%s, %s, %s,'null','null', %s, %s, %s)",
                                 (name, price, description, available, category, picture))
                    mysql.connection.commit()
                    curs.close()
                    flash('Product added successful', 'success')
                    return redirect(url_for('admin_add_product'))
                else:
                    flash('Picture not save', 'danger')
                    return redirect(url_for('admin_add_product'))
            else:
                flash('File not supported', 'danger')
                return redirect(url_for('admin_add_product'))
        else:
            flash('Please fill up all form', 'danger')
            return redirect(url_for('admin_add_product'))
    else:
        return render_template('pages/add_product.html')

@app.route('/admin_add_workshop', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_add_workshop():
    if request.method == 'POST':
        name = request.form.get('name')
        price = request.form['price']
        description = request.form['description']
        available = request.form['available']
        location = request.form['location']
        category = request.form['category']
        file = request.files['picture']
        category=category.strip()
        name = name.strip()
        description = description.strip()
        location = location.strip()
        if name!="" and price and description!="" and available and location!="" and category!="" and file:
            pic = file.filename
            photo = pic.replace("'", "")
            picture = photo.replace(" ", "_")
            if picture.lower().endswith(('.png', '.jpg', '.jpeg')):
                save_photo = photos.save(file, folder="workshops/"+location)
                if save_photo:
                    # Create Cursor
                    curs = mysql.connection.cursor()
                    if location == 'hyderabad':
                        locationID = 1
                    elif location == 'bangalore':
                        locationID = 3
                    elif location == 'mumbai':
                        locationID = 2

                    curs.execute("INSERT INTO workshops(workshop,price,description,available,Location,category,picture,locationID)"
                                 "VALUES(%s, %s, %s, %s, %s, %s, %s,%s)",
                                 (name, price, description, available, location, category, picture,locationID))
                    mysql.connection.commit()
                    curs.close()

                    flash('Workshop added successful', 'success')
                    return redirect(url_for('admin_add_workshop'))
                else:
                    flash('Picture not save', 'danger')
                    return redirect(url_for('admin_add_workshop'))
            else:
                flash('File not supported', 'danger')
                return redirect(url_for('admin_add_workshop'))
        else:
            flash('Please fill up all form', 'danger')
            return redirect(url_for('admin_add_workshop'))
    else:
        return render_template('pages/add_workshop.html')

@app.route('/edit_product', methods=['POST', 'GET'])
@is_admin_logged_in
def edit_product():
    if 'id' in request.args:
        product_id = request.args['id']
        curso = mysql.connection.cursor()
        res = curso.execute("SELECT * FROM products WHERE id=%s", (product_id,))
        product = curso.fetchall()
        curso.execute("SELECT * FROM product_level WHERE product_id=%s", (product_id,))
        product_level = curso.fetchall()
        if res:

            if request.method == 'POST':

                name = request.form.get('name')
                price = request.form['price']
                description = request.form['description']
                available = request.form['available']
                category = request.form['category']
                item = request.form['item']
                code = request.form['code']
                file = request.files['picture']
                # Create Cursor
                if name and price and description and available and category and item and code and file:
                    pic = file.filename
                    photo = pic.replace("'", "")
                    picture = photo.replace(" ", "_")
                    if picture.lower().endswith(('.png', '.jpg', '.jpeg')):
                        save_photo = photos.save(file, folder="product/"+category)
                        if save_photo:
                            # Create Cursor
                            cur = mysql.connection.cursor()
                            exe = curso.execute(
                                "UPDATE products SET pName=%s, price=%s, description=%s, available=%s, category=%s, item=%s, pCode=%s, picture=%s WHERE id=%s",
                                (name, price, description, available, category, item, code, pic, product_id))

                            if exe:
                                if category == 'tshirt':
                                    level = request.form.getlist('tshirt')
                                    for lev in level:
                                        yes = 'yes'
                                        query = 'UPDATE product_level SET {field}=%s WHERE product_id=%s'.format(
                                            field=lev)
                                        cur.execute(query, (yes, product_id))
                                        # Commit cursor
                                        mysql.connection.commit()
                                elif category == 'wallet':
                                    level = request.form.getlist('wallet')
                                    for lev in level:
                                        yes = 'yes'
                                        query = 'UPDATE product_level SET {field}=%s WHERE product_id=%s'.format(
                                            field=lev)
                                        cur.execute(query, (yes, product_id))
                                        # Commit cursor
                                        mysql.connection.commit()
                                elif category == 'belt':
                                    level = request.form.getlist('belt')
                                    for lev in level:
                                        yes = 'yes'
                                        query = 'UPDATE product_level SET {field}=%s WHERE product_id=%s'.format(
                                            field=lev)
                                        cur.execute(query, (yes, product_id))
                                        # Commit cursor
                                        mysql.connection.commit()
                                elif category == 'shoes':
                                    level = request.form.getlist('shoes')
                                    for lev in level:
                                        yes = 'yes'
                                        query = 'UPDATE product_level SET {field}=%s WHERE product_id=%s'.format(
                                            field=lev)
                                        cur.execute(query, (yes, product_id))
                                        # Commit cursor
                                        mysql.connection.commit()
                                else:
                                    flash('Product level not fund', 'danger')
                                    return redirect(url_for('admin_add_product'))
                                flash('Product updated', 'success')
                                return redirect(url_for('edit_product'))
                            else:
                                flash('Data updated', 'success')
                                return redirect(url_for('edit_product'))
                        else:
                            flash('Pic not upload', 'danger')
                            return render_template('edit_product.html', product=product,
                                                   product_level=product_level)
                    else:
                        flash('File not support', 'danger')
                        return render_template('edit_product.html', product=product,
                                               product_level=product_level)
                else:
                    flash('Fill all field', 'danger')
                    return render_template('edit_product.html', product=product,
                                           product_level=product_level)
            else:

                return render_template('pages/edit_product.html', product=product, product_level=product_level)
        else:
            return redirect(url_for('admin_login'))
    else:
        return redirect(url_for('admin_login'))

@app.route('/remove_workshop', methods=['POST', 'GET'])
@is_admin_logged_in
def remove_workshop():
    if 'id' in request.args:
        workshop_id = request.args['id']
        curso = mysql.connection.cursor()
        curso.execute("DELETE FROM workshops WHERE id=%s",(workshop_id))
        mysql.connection.commit()
        flash('workshop removed', 'success')
        return redirect(url_for('all_workshops'))


@app.route('/remove_cart', methods=['POST', 'GET'])
@is_logged_in
def remove_cart():
    if 'id' in request.args:
        cart_id = request.args['id']
        curso = mysql.connection.cursor()
        curso.execute("DELETE FROM cart WHERE cid=%s",[cart_id])
        mysql.connection.commit()
        flash('cart item removed', 'success')
        return redirect(url_for('cart'))

@app.route('/remove_product', methods=['POST', 'GET'])
@is_admin_logged_in
def remove_product():
    if 'id' in request.args:
        product_id = request.args['id']
        curso = mysql.connection.cursor()
        curso.execute("DELETE FROM products WHERE id=%s",[product_id])
        mysql.connection.commit()
        flash('product removed', 'success')
        return redirect(url_for('admin'))

@app.route('/search', methods=['POST', 'GET'])
def search():
    form = OrderForm(request.form)
    if 'q' in request.args:
        q = request.args['q']
        # Create cursor
        cur = mysql.connection.cursor()
        # Get message
        query_string = "SELECT * FROM products WHERE pName LIKE %s ORDER BY id ASC"
        cur.execute(query_string, ('%' + q + '%',))
        products = cur.fetchall()
        # Close Connection
        cur.close()
        flash('Showing result for: ' + q, 'success')
        return render_template('search.html', products=products, form=form)
    else:
        flash('Search again', 'danger')
        return render_template('search.html')


@app.route('/profile')
@is_logged_in
def profile():
    if 'user' in request.args:
        q = request.args['user']
        curso = mysql.connection.cursor()
        curso.execute("SELECT * FROM users WHERE id=%s", (q,))
        result = curso.fetchone()
        if result:
            if result['id'] == session['uid']:
                curso.execute("SELECT * FROM orders WHERE uid=%s ORDER BY id ASC", (session['uid'],))
                res = curso.fetchall()
                return render_template('profile.html', result=res)
            else:
                flash('Unauthorised', 'danger')
                return redirect(url_for('login'))
        else:
            flash('Unauthorised! Please login', 'danger')
            return redirect(url_for('login'))
    else:
        flash('Unauthorised', 'danger')
        return redirect(url_for('login'))


class UpdateRegisterForm(Form):
    name = StringField('Full Name', [validators.length(min=3, max=50)],
                       render_kw={'autofocus': True, 'placeholder': 'Full Name'})
    email = EmailField('Email', [validators.DataRequired(), validators.Email(), validators.length(min=4, max=25)],
                       render_kw={'placeholder': 'Email'})
    password = PasswordField('Password', [validators.length(min=3)],
                             render_kw={'placeholder': 'Password'})
    mobile = StringField('Mobile', [validators.length(min=11, max=15)], render_kw={'placeholder': 'Mobile'})

@app.route('/settings', methods=['POST', 'GET'])
@is_logged_in
def settings():
    form = UpdateRegisterForm(request.form)
    if 'user' in request.args:
        q = request.args['user']
        curso = mysql.connection.cursor()
        curso.execute("SELECT * FROM users WHERE id=%s", (q,))
        result = curso.fetchone()
        if result:
            if result['id'] == session['uid']:
                if request.method == 'POST' and form.validate():
                    name = request.form.get('name')
                    email = request.form.get('email')
                    password = sha256_crypt.encrypt(str(request.form.get('pass')))
                    mobile = request.form.get('mobile')
                    #print(name)
                    #print(email)
                    #print(password)
                    #print(mobile)
                    # Create Cursor
                    cur = mysql.connection.cursor()
                    exe = cur.execute("UPDATE users SET name=%s, email=%s, password=%s, mobile=%s WHERE id=%s",
                                      (name, email, password, mobile, q))
                    if exe:
                        flash('Profile updated', 'success')
                        return render_template('user_settings.html', result=result, form=form)
                    else:
                        flash('Profile not updated', 'danger')
                return render_template('user_settings.html', result=result, form=form)
            else:
                flash('Unauthorised', 'danger')
                return redirect(url_for('login'))
        else:
            flash('Unauthorised! Please login', 'danger')
            return redirect(url_for('login'))
    else:
        flash('Unauthorised', 'danger')
        return redirect(url_for('login'))


class DeveloperForm(Form):  #
    id = StringField('', [validators.length(min=1)],
                     render_kw={'placeholder': 'Input a product id...'})


@app.route('/developer', methods=['POST', 'GET'])
def developer():
    form = DeveloperForm(request.form)
    if request.method == 'POST' and form.validate():
        q = form.id.data
        curso = mysql.connection.cursor()
        result = curso.execute("SELECT * FROM products WHERE id=%s", (q,))
        if result > 0:
            x = content_based_filtering(q)
            wrappered = wrappers(content_based_filtering, q)
            execution_time = timeit.timeit(wrappered, number=0)
            seconds = ((execution_time / 1000) % 60)
            return render_template('developer.html', form=form, x=x, execution_time=seconds)
        else:
            nothing = 'Nothing found'
            return render_template('developer.html', form=form, nothing=nothing)
    else:
        return render_template('developer.html', form=form)


if __name__ == '__main__':
    app.run(host='0.0.0.0',port=80)
