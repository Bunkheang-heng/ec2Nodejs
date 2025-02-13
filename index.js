import express from "express";
import { createClient } from "@supabase/supabase-js"; 
import jwt from 'jsonwebtoken';
import dotenv from "dotenv";
dotenv.config();

const app = express();

// Add middleware to parse JSON bodies
app.use(express.json());

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
);

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// User Registration
app.post("/register", async (req, res) => {
  try {
    const { sname, semail, spass, role } = req.body;
    
    if (!['admin', 'student'].includes(role)) {
      return res.status(400).json({ error: "Invalid role. Must be 'admin' or 'student'" });
    }

    // Check if user already exists
    const { data: existingUser, error: checkError } = await supabase
      .from('users')
      .select('*')
      .eq('email', semail)
      .single();

    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    // Store user details in users table
    const { data, error } = await supabase
      .from('users')
      .insert([{
        name: sname,
        email: semail,
        password: spass,
        role
      }])
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({ message: "User registered successfully", user: data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// User Login
app.post("/login", async (req, res) => {
  try {
    const { semail, spass } = req.body;
    
    // Check user credentials
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', semail)
      .eq('password', spass)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ 
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Middleware to verify token
const verifyAuth = (requiredRole) => async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: "No token provided" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get user from database
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', decoded.userId)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: "Unauthorized access" });
    }

    if (requiredRole && user.role !== requiredRole) {
      return res.status(403).json({ error: "Insufficient permissions" });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// Get all users (admin only)
app.get("/users", verifyAuth('admin'), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user profile
app.get("/profile", verifyAuth(), async (req, res) => {
  res.json(req.user);
});

// Update user (admin can update anyone, students can only update themselves)
app.put("/users/:id", verifyAuth(), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, semail } = req.body;
    
    // Check if user has permission to update
    if (req.user.role !== 'admin' && req.user.id !== id) {
      return res.status(403).json({ error: "Insufficient permissions" });
    }

    // Create update object with only provided fields
    const updateData = {};
    if (name) updateData.name = name;
    if (semail) updateData.email = semail;

    const { data, error } = await supabase
      .from('users')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;
    if (!data) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete user (admin only)
app.delete("/users/:id", verifyAuth('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if user exists before deleting
    const { data: existingUser, error: checkError } = await supabase
      .from('users')
      .select('*')
      .eq('id', id)
      .single();

    if (checkError || !existingUser) {
      return res.status(404).json({ error: "User not found" });
    }

    // Prevent deleting the last admin
    if (existingUser.role === 'admin') {
      const { data: adminCount, error: countError } = await supabase
        .from('users')
        .select('id')
        .eq('role', 'admin');

      if (!countError && adminCount.length === 1) {
        return res.status(400).json({ error: "Cannot delete the last admin user" });
      }
    }

    const { error: deleteError } = await supabase
      .from('users')
      .delete()
      .eq('id', id);

    if (deleteError) throw deleteError;
    
    res.json({ message: "User deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/", (req, res) => {
  res.send("Hello World");
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
