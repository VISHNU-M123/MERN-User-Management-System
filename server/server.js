import express from "express";
import cors from "cors";
import 'dotenv/config';
import cookieParser from "cookie-parser";
import mongoose from "mongoose";
import userRouter from "./routes/userRoutes.js"
import authRouter from "./routes/authRoutes.js";

mongoose.connect('mongodb://127.0.0.1:27017/user-management-MERN');

const app = express();
const port = process.env.PORT || 4000;

const allowedOrigins = ['http://localhost:5173']

app.use(express.json());
app.use(cookieParser());
app.use(cors({origin:allowedOrigins, credentials: true}));

app.use('/api/auth', userRouter);
app.use('/api/user', authRouter);

app.listen(port, () => console.log(`Server started on PORT: ${port}`))