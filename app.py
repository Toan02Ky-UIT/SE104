from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shoe_store.db'
db = SQLAlchemy(app)


# MODELS
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(20), default='customer')  # customer, staff, admin

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    detail = db.Column(db.Text)
    image_url = db.Column(db.String(255))
    
    
    sizes = db.relationship('ProductSize', backref='product', cascade='all, delete-orphan')
    order_details = db.relationship('OrderDetail', backref='product', lazy=True)

class ProductSize(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    size = db.Column(db.String(10), nullable=False)
    stock = db.Column(db.Integer, default=0)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_price = db.Column(db.Float, default=0, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    payment_method = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now())
    status_updated_at = db.Column(db.DateTime) 
    cancellation_reason = db.Column(db.String(255))

    user = db.relationship('User', backref='orders')
    details = db.relationship('OrderDetail', backref='order', lazy=True)

class OrderDetail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    size_id = db.Column(db.Integer, db.ForeignKey('product_size.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    price = db.Column(db.Float, nullable=False)

    size = db.relationship('ProductSize', backref='product_size')

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    size_id = db.Column(db.Integer, db.ForeignKey('product_size.id'))
    quantity = db.Column(db.Integer, default=1)

    user = db.relationship('User', backref='cart_items')
    product = db.relationship('Product', backref='cart_items')
    size = db.relationship('ProductSize', backref='cart_items')

class InventoryLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity_change = db.Column(db.Integer)
    note = db.Column(db.String(200))


# UTILS
from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            user = User.query.get(session['user_id'])
            if not user or user.role != role:
                flash('Không có quyền truy cập')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper


# ROUTES
@app.route('/')
def home():
    products = Product.query.all()
    return render_template('home.html', products=products)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Đăng ký thành công!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role   # Lưu role vào session
            if user.role == 'admin':
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('home'))
        else:
            flash('Sai tài khoản hoặc mật khẩu!', 'danger')
    return render_template('login.html')


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    user = User.query.get(session.get('user_id'))
    if request.method == 'POST':
        current_pass = request.form['current_pass'].strip()
        new_pass = request.form['new_pass'].strip()
        confirm_pass = request.form['confirm_pass'].strip()

        if not check_password_hash(user.password, current_pass):
            flash('Mật khẩu hiện tại chưa chính xác!', 'danger')
        elif new_pass == '':
            flash('Mật khẩu chưa được nhập!', 'danger')
        elif new_pass != confirm_pass:
            flash('Xác nhận mật khẩu chưa khớp!', 'danger')
        else:
            user.password = generate_password_hash(new_pass)
            db.session.commit()
            flash('Cập nhật mật khẩu thành công!', 'success')
            return redirect(url_for('user_info'))
    return render_template('change_password.html')

@app.context_processor
def inject_user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return dict(current_user=user)
    return dict(current_user=None)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/user_info', methods=['GET', 'POST'])

@login_required
def user_info():
    user = User.query.get(session.get('user_id'))
    return render_template('user_info.html', user=user)




@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = User.query.get(session.get('user_id'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']

        if phone and address:
            user.username = username
            user.email = email
            user.phone = phone
            user.address = address
            db.session.commit()
            flash("Cập nhật thông tin thành công.", "success")
            return redirect(url_for('user_info'))
        else:
            flash("Vui lòng nhập đầy đủ thông tin.", "danger")

        
    return render_template('edit_profile.html', user=user)



@app.route('/cart')
@login_required
def cart():
    user_id = session.get('user_id')
    cart_items = Cart.query.filter_by(user_id=user_id).all()
    cart_details = []
    total = 0

    for item in cart_items:
        product = Product.query.get(item.product_id)
        size = ProductSize.query.get(item.size_id)
        if product and size:
            if size.stock < item.quantity:
                item.quantity = size.stock
                db.session.commit()
                flash(f"Sản phẩm {product.name} - Size {size.size} chỉ còn {size.stock}.!", "danger")

            item_total = product.price * item.quantity
            total += item_total  

            cart_details.append({ 
                'id': item.id,
                'name': product.name,
                'price': product.price,
                'quantity': item.quantity,
                'image': product.image_url,
                'size': size.size
            })
        else:
            db.session.delete(item)
            db.session.commit()

    return render_template('cart.html', cart_details=cart_details, total=total)

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    # Thêm sản phẩm vào giỏ
    user_id = session.get('user_id')
    size_id = request.form.get('size_id')
    
    product = Product.query.get(product_id)
    size = ProductSize.query.get(size_id)


    if size.stock == 0:
        flash("Size này hết hàng.", "danger")
        return redirect(url_for('home'))

    existing_item = Cart.query.filter_by(user_id=user_id, product_id=product_id, size_id=size_id).first()
    
    if existing_item:
        if existing_item.quantity < size.stock:
            existing_item.quantity += 1
            db.session.commit()
            flash("✅ Đã thêm vào giỏ hàng!", "success")
        else:
            flash("Số lượng sản phẩm trong kho không đủ.", "danger")
    else:
        new_item = Cart(user_id=user_id, product_id=product_id, size_id=size_id, quantity=1)
        db.session.add(new_item)
        db.session.commit()
        flash("✅ Đã thêm vào giỏ hàng!", "success")

    return redirect(url_for('home'))  

@app.route('/update_quantity/<int:product_id>', methods=['POST'])

def update_quantity(product_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Vui lòng đăng nhập'}), 403
    
    data = request.json
    quantity = int(data['quantity'])

    if quantity < 1:
        quantity = 1

    # Giả sử bạn có dòng CartItem
    item = Cart.query.filter_by(id=product_id, user_id=session['user_id']).first()
    if item is None:
        return jsonify({'error': 'Sản phẩm không tìm thấy'}), 404
    
    item.quantity = quantity
    db.session.commit()

    return jsonify({'success': True, 'new_quantity': item.quantity})


@app.route('/remove_from_cart/<int:item_id>', methods=['POST'])
@login_required
def remove_from_cart(item_id):
    user_id = session.get('user_id')
    
    
    item = Cart.query.filter_by(id=item_id, user_id=user_id).first()

    if item:
        db.session.delete(item)
        db.session.commit()
        flash("Đã xóa sản phẩm")

    else:
        flash("Không tìm thấy sản phẩm.", "danger")
    return redirect(url_for('cart'))


@app.context_processor
def inject_cart_count():
    if 'user_id' in session:
        count = db.session.query(db.func.sum(Cart.quantity)).filter_by(user_id=session['user_id']).scalar() or 0
        return {'cart_count': count}
    return {'cart_count': 0}


@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    cart_items = Cart.query.filter_by(user_id=user_id).all()

    if not user.phone or not user.address:
        flash("Vui lòng hoàn thành số điện thoại và địa chỉ trước khi thanh toán.", "danger")
        return redirect(url_for('edit_profile'))

    if request.method == 'POST':
        payment_method = request.form.get('payment_method')
        total = 0

        # Tính tổng tiền
        for item in cart_items:
            product = Product.query.get(item.product_id)
            size = ProductSize.query.get(item.size_id)
            if product and size:
                total += product.price * item.quantity
                size.stock -= item.quantity
        # Tạo đơn hàng
        new_order = Order(
            user_id=user_id,
            total_price=total,
            status='Pending',
            payment_method=payment_method
        )
        try:
            db.session.add(new_order)
            db.session.commit()  

            # Tạo chi tiết đơn hàng
            for item in cart_items:
                product = Product.query.get(item.product_id)
                size = ProductSize.query.get(item.size_id)
                if product and size:
                    order_detail = OrderDetail(
                    order_id=new_order.id,
                    product_id=product.id,
                    size_id=size.id,
                    quantity=item.quantity,
                    price=product.price
                )
                db.session.add(order_detail)
            log = InventoryLog(
                    product_id=product.id,
                    
                    quantity_change=-item.quantity,
                    note=f"Khách hàng #{user_id} mua size {size.size}"
                )
            db.session.add(log)

            db.session.commit()

            Cart.query.filter_by(user_id=user_id).delete()
            db.session.commit()  
            
            flash("Đơn hàng đã được ghi nhận!", "success")
            return redirect(url_for('thanks'))

        except Exception as e:
            db.session.rollback()
            flash(f"Lỗi khi tạo đơn hàng: {e}", "danger")
            return redirect(url_for('cart'))

    return render_template('checkout.html', cart_items=cart_items)


@app.route('/thanks')
@login_required
def thanks():
    return render_template('thanks.html')


@app.route('/orders')
@login_required
def orders():
    user_id = session.get('user_id')
    user_orders = Order.query.filter_by(user_id=user_id).all()
    return render_template('orders.html', orders=user_orders)



@app.route('/order_detail/<int:order_id>', methods=['GET'])
@login_required
def order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    return render_template('order_detail.html', order=order)


# ADMIN: Quản lý nhân viên/khách hàng, phân quyền, thống kê

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('home'))

    products = Product.query.all()
    orders = Order.query.all()
    users = User.query.all()
    return render_template('admin.html', products=products, orders=orders, users=users)

@app.route('/add_product', methods=['POST'])
def add_product():
    name = request.form['name']
    price = float(request.form['price'])
    description = request.form['description']
    detail = request.form.get('detail', '')
    image_url = request.form['image_url']

    sizes = request.form.getlist('sizes[]')
    stocks = request.form.getlist('stocks[]')

    if not name or price <= 0:
        flash("Vui lòng nhập đầy đủ tên sản phẩm và giá.", "danger")
        return redirect(url_for('admin'))
        
    if not sizes or not stocks or len(sizes) != len(stocks):
        flash("Vui lòng thêm đầy đủ size và số lượng.", "danger")
        return redirect(url_for('admin'))

    product = Product(name=name, price=price, description=description, detail=detail, image_url=image_url)
    db.session.add(product)
    db.session.commit()

    for size, stock in zip(sizes, stocks):
        ps = ProductSize(product_id=product.id, size=int(size), stock=int(stock))
        db.session.add(ps)

    db.session.commit()

    flash("Thêm sản phẩm thành công!", "success")
    return redirect(url_for('admin'))

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)


@app.route('/get_stock')
def get_stock():
    product_id = request.args.get('id', type=int)
    size = request.args.get('size', default='', type=str)

    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    
    if size == '':
        stock = sum(s.stock for s in product.sizes)
    else:
        matching = [s for s in product.sizes if str(s.size) == size]
        if matching:
            stock = matching[0].stock
        else:
            stock = 0
    
    return jsonify({'stock': stock})


@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('home'))
    product = Product.query.get_or_404(product_id)
    if request.method == 'POST':
        product.name = request.form['name']
        product.price = float(request.form['price'])

        product.description = request.form['description']
        product.detail = request.form['detail']
        product.image_url = request.form['image_url']

        size_ids = request.form.getlist('size_ids')
        sizes = request.form.getlist('sizes')
        stocks = request.form.getlist('stocks')

        for size_id, size, stock in zip(size_ids, sizes, stocks):
            ps = ProductSize.query.get(size_id)
            ps.size = int(size)
            ps.stock = int(stock)
            db.session.add(ps)

        db.session.commit()

        flash('Cập nhật sản phẩm thành công!', 'success')
        return redirect(url_for('admin'))
    return render_template('edit_product.html', product=product)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('home'))
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash("Xóa sản phẩm thành công!", "success")
    return redirect(url_for('admin'))

@app.route('/view_order/<int:order_id>', methods=['GET'])
@login_required
def view_order(order_id):
    order = Order.query.get_or_404(order_id)
    customer = User.query.get_or_404(order.user_id)
    order_details = order.details

    total = sum(item.quantity * item.price for item in order_details)

    return render_template('view_order.html',
                           order=order,
                           customer=customer,
                           order_details=order_details,
                           total=total)


@app.route('/update_order_status/<int:order_id>', methods=['GET', 'POST'])
@login_required
def update_order_status(order_id):
    if 'user_id' not in session or session.get('role') not in ['admin', 'staff']:
        return redirect(url_for('home'))
    order = Order.query.get_or_404(order_id)

    if order.status == "Đã hủy":
        flash("Đơn hàng này đã bị hủy, bạn KHÔNG được thay đổi.", "danger")
        return redirect(url_for('admin'))
    

    new_status = request.form['status']
    reason = request.form.get('cancellation_reason', '').strip()

    if new_status == "Đã hủy":

        if not reason:
            flash("Vui lòng nhập lý do hủy đơn.", "danger")
            if session.get('role') == 'admin':
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('staff'))
        
        # Cộng lại số sản phẩm vào kho
        for item in order.details:
            
            size = ProductSize.query.get(item.size_id)
            if size:
                size.stock += item.quantity

        order.cancellation_reason = reason
        order.status = new_status
        db.session.commit()
        flash("Đơn hàng đã được hủy.", "success")

    elif new_status:
        order.status = new_status
        db.session.commit()
        flash("Cập nhật trạng thái thành công.", "success")

    if session.get('role') == 'admin':
        return redirect(url_for('admin'))
    else:
        return redirect(url_for('staff'))

@app.route('/revenue_report')
@login_required
def revenue_report():
    if session.get('role') != 'admin':
        flash("Bạn không có quyền truy cập.", "danger")
        return redirect(url_for('home'))

    # Doanh thu = tổng tiền của đơn hàng đã nhận
    orders = Order.query.filter_by(status='Đã nhận').all()
    total_revenue = sum(order.total_price for order in orders)

    # Đếm đơn hàng theo trạng thái
    from collections import Counter
    all_orders = Order.query.all()
    status_count = Counter(order.status for order in all_orders)

    return render_template('admin.html', total_revenue=total_revenue, status_count=status_count)


@app.route('/admin/users')
@role_required('admin')
def manage_users():
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/admin/set_role/<int:user_id>/<role>')
@login_required
@role_required('admin')
def set_role(user_id, role):
    user = User.query.get(user_id)
    if role in ['admin', 'staff', 'customer']:
        user.role = role
        db.session.commit()
    return redirect(url_for('manage_users'))



@app.route('/set_staff/<int:user_id>', methods=['POST'])
@login_required
def set_staff(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Bạn không có quyền thực hiện!", "danger")
        return redirect(url_for('home'))
        
    user = User.query.get(user_id)
    if not user:
        flash("Tài khoản không tồn tại!", "danger")
        return redirect(url_for('admin'))
        
    new_role = request.form['role']

    if new_role not in ['user', 'staff', 'admin']:
        flash("Vai trò không chính xác!", "danger")
        return redirect(url_for('admin'))
        
    user.role = new_role
    db.session.commit()
    flash("Cập nhật quyền tài khoản thành công!", "success")
    return redirect(url_for('admin'))


# STAFF: Quản lý sản phẩm và kho
@app.route('/staff')
@login_required
def staff():
    if 'user_id' not in session or session.get('role') not in ['admin', 'staff']:
        return redirect(url_for('home'))
    products = Product.query.all()
    return render_template('staff.html', products=products)

@app.route('/add_stock/<int:product_id>/<int:size_id>', methods=['POST'])
@login_required
def add_stock(product_id, size_id):
    if 'user_id' not in session or session.get('role') not in ['admin', 'staff']:
        return redirect(url_for('home'))
    size_entry = ProductSize.query.get_or_404(size_id)
    try:
        additional = int(request.form['additional'])
        if additional < 0:
            raise ValueError("Số lượng phải lớn hơn hoặc bằng 0.")

        size_entry = ProductSize.query.get_or_404(size_id)
        size_entry.stock += additional
        db.session.commit()

        flash(f"Đã thêm {additional} sản phẩm size {size_entry.size} vào kho.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Lỗi khi nhập kho: {e}", "danger")

    return redirect(url_for('staff'))

@app.route('/staff/orders')
@login_required
def staff_orders():
    if 'user_id' not in session or session.get('role') not in ['staff']:
        flash("Bạn không có quyền truy cập.", "danger")
        return redirect(url_for('home'))

    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template('staff.html', orders=orders)

@app.route('/staff')
@login_required
def inventory():
    if session.get('role') not in ['admin', 'staff']:
        return redirect(url_for('home'))

    products = Product.query.all()

    # Kiểm tra size nào dưới 5
    low_stock_items = ProductSize.query.filter(ProductSize.stock < 5).all()

    return render_template('staff.html', products=products, low_stock_items=low_stock_items)






def create_admin():
    if not User.query.filter_by(username="admin").first():
        admin = User(
            username="admin",
            email="admin@example.com",
            password=generate_password_hash("admin123"), 
            role="admin"
        )
        db.session.add(admin)
        db.session.commit()
        print("Tài khoản quản lý đã được tạo.")




if __name__ == '__main__':
    
    with app.app_context():
        db.create_all()
        create_admin()
    app.run(debug=True)
