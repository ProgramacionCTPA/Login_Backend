const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(express.static("public"));

app.use(cors({
  origin: "https://login2026pw.netlify.app",
  methods: ["GET", "POST"],
}));

mongoose.connect(process.env.MONGO_URI)
  .then(() => {
     console.log("MongoDB conectado");
  })
  .catch(err => {
     console.log("ERROR MONGODB:", err);
  });

const User = require("./models/User");

// REGISTRO
app.post("/register", async (req, res) => {
   try {
      const { username, password } = req.body;

      const userExists = await User.findOne({ username });
      if (userExists) return res.status(400).json({ message: "Usuario ya existe" });

      const hashedPassword = await bcrypt.hash(password, 10);

      const user = new User({
         username,
         password: hashedPassword
      });

      await user.save();
      res.json({ message: "Usuario registrado correctamente" });
}
catch (error) {
   console.log("LOGIN ERROR:", error);
   res.status(500).json({ message: error.message });
}
});

// LOGIN
app.post("/login", async (req, res) => {
   try {
      const { username, password } = req.body;

      const user = await User.findOne({ username });
      if (!user) return res.status(400).json({ message: "Usuario no existe" });

      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) return res.status(400).json({ message: "Contraseña incorrecta" });

      const token = jwt.sign({ id: user._id, username: user.username }, "secretkey", { expiresIn: "1h" });

      res.json({ token, username: user.username });

   } catch (error) {
      res.status(500).json({ message: "Error en servidor" });
   }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));




