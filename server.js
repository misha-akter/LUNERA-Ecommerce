
const express = require("express");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcrypt");
require("dotenv").config();

const pool = require("./db");
const app = express();
const PORT = process.env.PORT || 3000;

if (
    !process.env.SESSION_SECRET ||
    !process.env.ADMIN_USERNAME ||
    !process.env.ADMIN_PASSWORD
) {
    throw new Error(
        "Please configure SESSION_SECRET, ADMIN_USERNAME and ADMIN_PASSWORD in .env"
    );
}

app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
    name: "lunera.admin.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "strict",
        secure: process.env.NODE_ENV === "production",
        maxAge: 30 * 60 * 1000
    }
}));

const publicPath = path.join(__dirname, "public");
app.use(express.static(publicPath));

// ---------------- HELPERS ----------------

function requireAdmin(req, res, next) {
    if (req.session && req.session.isAdmin === true) {
        return next();
    }

    return res.status(401).json({
        success: false,
        message: "Please log in as admin."
    });
}

function requireCustomer(req, res, next) {
    if (
        req.session &&
        Number.isSafeInteger(Number(req.session.customerId)) &&
        Number(req.session.customerId) > 0
    ) {
        return next();
    }

    return res.status(401).json({
        success: false,
        message: "Please log in to your customer account."
    });
}

function validEmail(email) {
    return typeof email === "string" &&
        email.trim().length <= 150 &&
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

function regenerateSession(req, res, next, sessionData, message) {
    req.session.regenerate(error => {
        if (error) return next(error);

        Object.assign(req.session, sessionData);

        req.session.save(saveError => {
            if (saveError) return next(saveError);

            res.json({
                success: true,
                message
            });
        });
    });
}

function handleServerError(res, error, label, message) {
    console.error(`${label}:`, error.message);

    if (error.code === "ER_DUP_ENTRY") {
        return res.status(409).json({
            success: false,
            message: "An account with this email already exists."
        });
    }

    return res.status(500).json({
        success: false,
        message
    });
}

// ---------------- PAGES ----------------

app.get("/", (req, res) => {
    res.sendFile(path.join(publicPath, "index.html"));
});

app.get("/admin", (req, res) => {
    res.sendFile(path.join(publicPath, "admin.html"));
});

app.get("/api", (req, res) => {
    res.json({
        success: true,
        message: "LUNÉRA E-commerce API is running!"
    });
});

// ---------------- ADMIN AUTH ----------------

app.post("/api/admin/login", (req, res, next) => {
    const { username, password } = req.body || {};

    if (
        typeof username !== "string" ||
        typeof password !== "string" ||
        username !== process.env.ADMIN_USERNAME ||
        password !== process.env.ADMIN_PASSWORD
    ) {
        return res.status(401).json({
            success: false,
            message: "Invalid admin username or password."
        });
    }

    regenerateSession(
        req,
        res,
        next,
        { isAdmin: true },
        "Admin login successful."
    );
});

app.get("/api/admin/me", (req, res) => {
    res.json({
        success: true,
        isAdmin: req.session?.isAdmin === true
    });
});

app.post("/api/admin/logout", (req, res, next) => {
    req.session.destroy(error => {
        if (error) return next(error);

        res.clearCookie("lunera.admin.sid", {
            httpOnly: true,
            sameSite: "strict",
            secure: process.env.NODE_ENV === "production"
        });

        res.json({
            success: true,
            message: "Logged out successfully."
        });
    });
});

// ---------------- CUSTOMER REGISTRATION ----------------

app.post("/api/customer/register", async (req, res) => {
    const { name, email, password, phone } = req.body || {};

    if (
        typeof name !== "string" ||
        !name.trim() ||
        name.trim().length > 100
    ) {
        return res.status(400).json({
            success: false,
            message: "Please enter a valid name (maximum 100 characters)."
        });
    }

    if (!validEmail(email)) {
        return res.status(400).json({
            success: false,
            message: "Please enter a valid email address."
        });
    }

    if (
        typeof password !== "string" ||
        password.length < 8 ||
        Buffer.byteLength(password, "utf8") > 72
    ) {
        return res.status(400).json({
            success: false,
            message: "Password must be at least 8 characters and no more than 72 bytes."
        });
    }

    const customerPhone = phone == null ? "" : phone;

    if (
        typeof customerPhone !== "string" ||
        customerPhone.trim().length > 30
    ) {
        return res.status(400).json({
            success: false,
            message: "Please enter a valid phone number."
        });
    }

    try {
        const normalizedEmail = email.trim().toLowerCase();

        const [existing] = await pool.query(
            "SELECT id FROM customers WHERE LOWER(email) = ? LIMIT 1",
            [normalizedEmail]
        );

        if (existing.length) {
            return res.status(409).json({
                success: false,
                message: "An account with this email already exists."
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const [result] = await pool.query(
            `INSERT INTO customers (name, email, password_hash, phone)
             VALUES (?, ?, ?, ?)`,
            [
                name.trim(),
                normalizedEmail,
                passwordHash,
                customerPhone.trim() || null
            ]
        );

        res.status(201).json({
            success: true,
            message: "Account created successfully. You can now log in.",
            customer: {
                id: result.insertId,
                name: name.trim(),
                email: normalizedEmail,
                phone: customerPhone.trim() || null
            }
        });
    } catch (error) {
        handleServerError(
            res,
            error,
            "Customer registration error",
            "Unable to create your account."
        );
    }
});

// ---------------- CUSTOMER LOGIN ----------------

app.post("/api/customer/login", async (req, res, next) => {
    const { email, password } = req.body || {};

    if (
        !validEmail(email) ||
        typeof password !== "string" ||
        !password.length ||
        Buffer.byteLength(password, "utf8") > 72
    ) {
        return res.status(400).json({
            success: false,
            message: "Please provide a valid email and password."
        });
    }

    try {
        const [customers] = await pool.query(
            `SELECT id, name, email, password_hash, phone
             FROM customers
             WHERE LOWER(email) = ?
             LIMIT 1`,
            [email.trim().toLowerCase()]
        );

        if (!customers.length) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });
        }

        const customer = customers[0];
        const passwordMatches = await bcrypt.compare(
            password,
            customer.password_hash
        );

        if (!passwordMatches) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });
        }

        req.session.regenerate(error => {
            if (error) return next(error);

            req.session.customerId = customer.id;

            req.session.save(saveError => {
                if (saveError) return next(saveError);

                res.json({
                    success: true,
                    message: "Login successful.",
                    customer: {
                        id: customer.id,
                        name: customer.name,
                        email: customer.email,
                        phone: customer.phone
                    }
                });
            });
        });
    } catch (error) {
        handleServerError(
            res,
            error,
            "Customer login error",
            "Unable to log in. Please try again."
        );
    }
});

// ---------------- CURRENT CUSTOMER ----------------

app.get("/api/customer/me", requireCustomer, async (req, res) => {
    try {
        const [customers] = await pool.query(
            `SELECT id, name, email, phone, created_at
             FROM customers WHERE id = ? LIMIT 1`,
            [req.session.customerId]
        );

        if (!customers.length) {
            return res.status(401).json({
                success: false,
                message: "Customer account not found. Please log in again."
            });
        }

        res.json({
            success: true,
            customer: customers[0]
        });
    } catch (error) {
        handleServerError(
            res,
            error,
            "Current customer error",
            "Unable to load customer information."
        );
    }
});

// ---------------- CUSTOMER LOGOUT ----------------

app.post("/api/customer/logout", (req, res, next) => {
    req.session.destroy(error => {
        if (error) return next(error);

        res.clearCookie("lunera.admin.sid", {
            httpOnly: true,
            sameSite: "strict",
            secure: process.env.NODE_ENV === "production"
        });

        res.json({
            success: true,
            message: "You have been logged out."
        });
    });
});

// ---------------- PRODUCTS ----------------

app.get("/api/products", async (req, res) => {
    try {
        const [products] = await pool.query(
            "SELECT * FROM products ORDER BY id DESC"
        );

        res.json({
            success: true,
            count: products.length,
            products
        });
    } catch (error) {
        handleServerError(
            res,
            error,
            "Products API error",
            "Failed to fetch products."
        );
    }
});

// ---------------- CHECKOUT ----------------

app.post("/api/orders", async (req, res) => {
    const {
        customer_name,
        customer_email,
        customer_phone,
        shipping_address,
        items
    } = req.body || {};

    if (
        typeof customer_name !== "string" ||
        !customer_name.trim() ||
        customer_name.trim().length > 100 ||
        !validEmail(customer_email) ||
        typeof customer_phone !== "string" ||
        !customer_phone.trim() ||
        customer_phone.trim().length > 30 ||
        typeof shipping_address !== "string" ||
        !shipping_address.trim() ||
        shipping_address.trim().length > 1000
    ) {
        return res.status(400).json({
            success: false,
            message: "Please provide valid customer and shipping information."
        });
    }

    if (!Array.isArray(items) || items.length === 0 || items.length > 100) {
        return res.status(400).json({
            success: false,
            message: "Your cart is empty or contains too many items."
        });
    }

    for (const item of items) {
        if (
            !item ||
            !Number.isSafeInteger(Number(item.id)) ||
            Number(item.id) <= 0 ||
            !Number.isSafeInteger(Number(item.quantity)) ||
            Number(item.quantity) <= 0 ||
            Number(item.quantity) > 10000
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid product or quantity in your cart."
            });
        }
    }

    // Combine repeated product IDs to avoid duplicate stock checks.
    const combinedItems = new Map();

    for (const item of items) {
        const id = Number(item.id);
        const quantity = Number(item.quantity);
        const combinedQuantity = (combinedItems.get(id) || 0) + quantity;

        if (!Number.isSafeInteger(combinedQuantity) || combinedQuantity > 10000) {
            return res.status(400).json({
                success: false,
                message: "Product quantity is too large."
            });
        }

        combinedItems.set(id, combinedQuantity);
    }

    let connection;
    let transactionStarted = false;

    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();
        transactionStarted = true;

        let totalAmount = 0;
        const verifiedItems = [];

        for (const [productId, quantity] of combinedItems) {
            const [products] = await connection.query(
                `SELECT id, name, price, stock
                 FROM products WHERE id = ? FOR UPDATE`,
                [productId]
            );

            if (!products.length) {
                const error = new Error(`Product ${productId} was not found.`);
                error.statusCode = 400;
                throw error;
            }

            const product = products[0];
            const price = Number(product.price);
            const stock = Number(product.stock);

            if (
                !Number.isFinite(price) ||
                !Number.isSafeInteger(stock) ||
                price < 0 ||
                stock < 0
            ) {
                throw new Error("Invalid product data in database.");
            }

            if (stock < quantity) {
                const error = new Error(
                    `Insufficient stock for ${product.name}. Available: ${stock}.`
                );
                error.statusCode = 409;
                throw error;
            }

            const subtotal = Math.round(price * quantity * 100) / 100;
            totalAmount = Math.round((totalAmount + subtotal) * 100) / 100;

            verifiedItems.push({
                productId,
                productName: product.name,
                price,
                quantity,
                subtotal
            });
        }

        const [orderResult] = await connection.query(
            `INSERT INTO orders
             (customer_name, customer_email, customer_phone,
              shipping_address, total_amount, status)
             VALUES (?, ?, ?, ?, ?, 'pending')`,
            [
                customer_name.trim(),
                customer_email.trim(),
                customer_phone.trim(),
                shipping_address.trim(),
                totalAmount
            ]
        );

        const orderId = orderResult.insertId;

        for (const item of verifiedItems) {
            await connection.query(
                `INSERT INTO order_items
                 (order_id, product_id, product_name, price, quantity, subtotal)
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [
                    orderId,
                    item.productId,
                    item.productName,
                    item.price,
                    item.quantity,
                    item.subtotal
                ]
            );

            const [updated] = await connection.query(
                `UPDATE products SET stock = stock - ?
                 WHERE id = ? AND stock >= ?`,
                [item.quantity, item.productId, item.quantity]
            );

            if (updated.affectedRows !== 1) {
                const error = new Error(
                    `Stock changed for ${item.productName}. Please try again.`
                );
                error.statusCode = 409;
                throw error;
            }
        }

        await connection.commit();
        transactionStarted = false;

        res.status(201).json({
            success: true,
            message: "Your order has been placed successfully!",
            orderId,
            totalAmount,
            status: "pending"
        });
    } catch (error) {
        if (connection && transactionStarted) {
            try {
                await connection.rollback();
            } catch (rollbackError) {
                console.error("Rollback error:", rollbackError.message);
            }
        }

        console.error("Order API error:", error.message);

        res.status(error.statusCode || 500).json({
            success: false,
            message: error.statusCode
                ? error.message
                : "Unable to place your order. Please try again."
        });
    } finally {
        if (connection) connection.release();
    }
});

// ---------------- ORDER DETAILS BY EMAIL ----------------

app.get("/api/orders/:id", async (req, res) => {
    const orderId = Number(req.params.id);
    const email = req.query.email;

    if (
        !Number.isSafeInteger(orderId) ||
        orderId <= 0 ||
        !validEmail(email)
    ) {
        return res.status(400).json({
            success: false,
            message: "Please provide a valid order ID and email."
        });
    }

    try {
        const [orders] = await pool.query(
            `SELECT id, customer_name, customer_email, customer_phone,
                    shipping_address, total_amount, status, created_at
             FROM orders
             WHERE id = ? AND LOWER(customer_email) = LOWER(?)
             LIMIT 1`,
            [orderId, email.trim()]
        );

        if (!orders.length) {
            return res.status(404).json({
                success: false,
                message: "Order not found for this email."
            });
        }

        const [items] = await pool.query(
            `SELECT product_id, product_name, price, quantity, subtotal
             FROM order_items WHERE order_id = ?`,
            [orderId]
        );

        res.json({
            success: true,
            order: { ...orders[0], items }
        });
    } catch (error) {
        handleServerError(
            res,
            error,
            "Order details API error",
            "Unable to fetch order details."
        );
    }
});

// ---------------- ORDER HISTORY BY EMAIL ----------------

app.get("/api/orders", async (req, res) => {
    const email = req.query.email;

    if (!validEmail(email)) {
        return res.status(400).json({
            success: false,
            message: "Please provide a valid email address."
        });
    }

    try {
        const [orders] = await pool.query(
            `SELECT id, total_amount, status, created_at
             FROM orders
             WHERE LOWER(customer_email) = LOWER(?)
             ORDER BY created_at DESC, id DESC`,
            [email.trim()]
        );

        if (!orders.length) {
            return res.json({ success: true, count: 0, orders: [] });
        }

        const ids = orders.map(order => order.id);
        const placeholders = ids.map(() => "?").join(", ");

        const [items] = await pool.query(
            `SELECT order_id, product_name, price, quantity, subtotal
             FROM order_items
             WHERE order_id IN (${placeholders})`,
            ids
        );

        const ordersWithItems = orders.map(order => ({
            ...order,
            items: items.filter(
                item => String(item.order_id) === String(order.id)
            )
        }));

        res.json({
            success: true,
            count: ordersWithItems.length,
            orders: ordersWithItems
        });
    } catch (error) {
        handleServerError(
            res,
            error,
            "Order history API error",
            "Unable to fetch order history."
        );
    }
});

// ---------------- LOGGED-IN CUSTOMER ORDER HISTORY ----------------

app.get("/api/customer/orders", requireCustomer, async (req, res) => {
    try {
        const [customers] = await pool.query(
            "SELECT email FROM customers WHERE id = ? LIMIT 1",
            [req.session.customerId]
        );

        if (!customers.length) {
            return res.status(401).json({
                success: false,
                message: "Customer account not found."
            });
        }

        const [orders] = await pool.query(
            `SELECT id, total_amount, status, created_at
             FROM orders
             WHERE LOWER(customer_email) = LOWER(?)
             ORDER BY created_at DESC, id DESC`,
            [customers[0].email]
        );

        if (!orders.length) {
            return res.json({
                success: true,
                count: 0,
                orders: []
            });
        }

        const ids = orders.map(order => order.id);
        const placeholders = ids.map(() => "?").join(", ");

        const [items] = await pool.query(
            `SELECT order_id, product_name, price, quantity, subtotal
             FROM order_items
             WHERE order_id IN (${placeholders})`,
            ids
        );

        res.json({
            success: true,
            count: orders.length,
            orders: orders.map(order => ({
                ...order,
                items: items.filter(
                    item => String(item.order_id) === String(order.id)
                )
            }))
        });
    } catch (error) {
        handleServerError(
            res,
            error,
            "Customer order history error",
            "Unable to load your order history."
        );
    }
});

// ---------------- LOGGED-IN CUSTOMER ORDER DETAILS ----------------

app.get("/api/customer/orders/:id", requireCustomer, async (req, res) => {
    const orderId = Number(req.params.id);

    if (!Number.isSafeInteger(orderId) || orderId <= 0) {
        return res.status(400).json({
            success: false,
            message: "Invalid order ID."
        });
    }

    try {
        const [orders] = await pool.query(
            `SELECT o.id, o.customer_name, o.customer_email,
                    o.customer_phone, o.shipping_address,
                    o.total_amount, o.status, o.created_at
             FROM orders o
             INNER JOIN customers c
                ON LOWER(c.email) = LOWER(o.customer_email)
             WHERE o.id = ? AND c.id = ?
             LIMIT 1`,
            [orderId, req.session.customerId]
        );

        if (!orders.length) {
            return res.status(404).json({
                success: false,
                message: "Order not found in your account."
            });
        }

        const [items] = await pool.query(
            `SELECT product_id, product_name, price, quantity, subtotal
             FROM order_items WHERE order_id = ?`,
            [orderId]
        );

        res.json({
            success: true,
            order: { ...orders[0], items }
        });
    } catch (error) {
        handleServerError(
            res,
            error,
            "Customer order details error",
            "Unable to load order details."
        );
    }
});

// ---------------- ADMIN DASHBOARD STATS ----------------

app.get("/api/admin/stats", requireAdmin, async (req, res) => {
    try {
        const [[orderStats]] = await pool.query(
            `SELECT COUNT(*) AS total_orders,
                    COALESCE(SUM(total_amount), 0) AS total_sales,
                    COALESCE(SUM(status = 'pending'), 0) AS pending_orders
             FROM orders`
        );

        const [[productStats]] = await pool.query(
            `SELECT COUNT(*) AS total_products,
                    COALESCE(SUM(stock), 0) AS total_stock
             FROM products`
        );

        res.json({
            success: true,
            stats: { ...orderStats, ...productStats }
        });
    } catch (error) {
        handleServerError(
            res,
            error,
            "Admin stats error",
            "Unable to load dashboard statistics."
        );
    }
});

// ---------------- ADMIN ORDER MANAGEMENT ----------------

app.get("/api/admin/orders", requireAdmin, async (req, res) => {
    try {
        const [orders] = await pool.query(
            `SELECT id, customer_name, customer_email, customer_phone,
                    shipping_address, total_amount, status, created_at
             FROM orders
             ORDER BY created_at DESC, id DESC`
        );

        const [items] = orders.length
            ? await pool.query(
                `SELECT order_id, product_name, price, quantity, subtotal
                 FROM order_items ORDER BY order_id DESC`
            )
            : [[]];

        res.json({
            success: true,
            orders: orders.map(order => ({
                ...order,
                items: items.filter(
                    item => String(item.order_id) === String(order.id)
                )
            }))
        });
    } catch (error) {
        handleServerError(
            res,
            error,
            "Admin orders error",
            "Unable to load orders."
        );
    }
});

app.patch("/api/admin/orders/:id/status", requireAdmin, async (req, res) => {
    const orderId = Number(req.params.id);
    const { status } = req.body || {};

    const allowedStatuses = [
        "pending",
        "processing",
        "shipped",
        "delivered",
        "cancelled"
    ];

    if (
        !Number.isSafeInteger(orderId) ||
        orderId <= 0 ||
        !allowedStatuses.includes(status)
    ) {
        return res.status(400).json({
            success: false,
            message: "Invalid order ID or status."
        });
    }

    try {
        const [result] = await pool.query(
            "UPDATE orders SET status = ? WHERE id = ?",
            [status, orderId]
        );

        if (!result.affectedRows) {
            const [found] = await pool.query(
                "SELECT id FROM orders WHERE id = ?",
                [orderId]
            );

            if (!found.length) {
                return res.status(404).json({
                    success: false,
                    message: "Order not found."
                });
            }
        }

        res.json({
            success: true,
            message: "Order status updated."
        });
    } catch (error) {
        handleServerError(
            res,
            error,
            "Update order status error",
            "Unable to update order status."
        );
    }
});

// ---------------- ADMIN PRODUCT MANAGEMENT ----------------

app.get("/api/admin/products", requireAdmin, async (req, res) => {
    try {
        const [products] = await pool.query(
            `SELECT id, name, description, price, image, stock
             FROM products ORDER BY id DESC`
        );

        res.json({ success: true, products });
    } catch (error) {
        handleServerError(
            res,
            error,
            "Admin products error",
            "Unable to load products."
        );
    }
});

app.patch("/api/admin/products/:id", requireAdmin, async (req, res) => {
    const productId = Number(req.params.id);
    const { price, stock } = req.body || {};

    if (
        !Number.isSafeInteger(productId) ||
        productId <= 0 ||
        price === undefined ||
        stock === undefined ||
        price === "" ||
        stock === "" ||
        !Number.isFinite(Number(price)) ||
        Number(price) < 0 ||
        !Number.isSafeInteger(Number(stock)) ||
        Number(stock) < 0
    ) {
        return res.status(400).json({
            success: false,
            message: "Provide a valid non-negative price and stock."
        });
    }

    try {
        const [result] = await pool.query(
            "UPDATE products SET price = ?, stock = ? WHERE id = ?",
            [Number(price), Number(stock), productId]
        );

        if (!result.affectedRows) {
            const [found] = await pool.query(
                "SELECT id FROM products WHERE id = ?",
                [productId]
            );

            if (!found.length) {
                return res.status(404).json({
                    success: false,
                    message: "Product not found."
                });
            }
        }

        res.json({
            success: true,
            message: "Product price and stock updated."
        });
    } catch (error) {
        handleServerError(
            res,
            error,
            "Update product error",
            "Unable to update product."
        );
    }
});

// ---------------- ERROR HANDLER ----------------

app.use((error, req, res, next) => {
    console.error("Unexpected server error:", error.message);

    if (res.headersSent) {
        return next(error);
    }

    res.status(500).json({
        success: false,
        message: "An unexpected server error occurred."
    });
});

// ---------------- SERVER ----------------

app.listen(PORT, () => {
    console.log(`LUNÉRA server running at http://localhost:${PORT}`);
    console.log(`Frontend folder: ${publicPath}`);
});
