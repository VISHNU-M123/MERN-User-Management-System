import express from 'express';
import userAuth from '../middleware/userAuth.js';
import { getUserData } from '../controllers/dashboardController.js';

const authRouter = express.Router();

authRouter.get('/data', userAuth, getUserData);

export default authRouter;