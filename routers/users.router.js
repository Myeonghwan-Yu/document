import express from 'express';
import { prisma } from '../models/index.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import authMiddleWare from '../middlewares/need-signin.middleware.js';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();

const router = express.Router();

router.post('/sign-up', async (req, res, next) => {
  const { email, password, passCon, isAdmin } = req.body;

  const isExistUser = await prisma.users.findFirst({
    where: { email },
  });

  if (typeof isAdmin !== 'boolean') {
    return res
      .status(400)
      .json({ message: 'isAdmin 필드가 유효하지 않습니다.' });
  }

  if (isExistUser) {
    return res.status(409).json({ message: '이미 존재하는 이메일입니다.' });
  }

  if (password.length < 6) {
    return res
      .status(400)
      .json({ message: '비밀번호는 최소 6자 이상이어야 합니다.' });
  }

  if (password !== passCon) {
    return res
      .status(400)
      .json({ message: '패스워드와 확인이 일치하지 않습니다.' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await prisma.users.create({
    data: {
      email,
      password: hashedPassword,
      isAdmin,
    },
  });
  return res.status(201).json({ message: '회원가입이 완료되었습니다.' });
});

router.post('/sign-in', async (req, res, next) => {
  const { email, password } = req.body;

  const user = await prisma.users.findFirst({
    where: { email },
  });

  if (!user) {
    return res.status(401).json({ message: '존재하지 않는 이메일입니다.' });
  }
  if (!(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: '비밀번호가 일치하지 않습니다.' });
  }

  const accessToken = jwt.sign(
    { userId: user.userId },
    process.env.ACCESS_TOKEN_SECRET_KEY,
    { expiresIn: '1h' }
  );

  const refreshToken = jwt.sign(
    { userId: user.userId },
    process.env.REFRESH_TOKEN_SECRET_KEY,
    { expiresIn: '1d' }
  );

  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: true,
    expires: new Date(Date.now() + 1 * 60 * 60 * 1000), // 1시간
  });

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: true,
    expires: new Date(Date.now() + 1 * 24 * 60 * 60 * 1000), // 1일
  });

  return res.status(200).json({ message: '로그인에 성공했습니다.' });
});

router.post('/refresh-token', async (req, res, next) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: '리프레시 토큰이 없습니다.' });
  }

  try {
    const decodedToken = jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET_KEY
    );

    if (decodedToken.exp * 1000 < Date.now()) {
      return res
        .status(403)
        .json({ message: '리프레시 토큰이 만료되었습니다.' });
    }
    const accessToken = jwt.sign(
      { userId: decodedToken.userId },
      process.env.ACCESS_TOKEN_SECRET_KEY,
      { expiresIn: '1h' }
    );

    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true,
      expires: new Date(Date.now() + 1 * 60 * 60 * 1000), // 1시간
    });

    return res
      .status(200)
      .json({ message: '새로운 Access Token이 발급되었습니다.' });
  } catch (error) {
    console.error('리프레시 토큰 검증 실패:', error);
    return res
      .status(403)
      .json({ message: '유효하지 않은 리프레시 토큰입니다.' });
  }
});

router.post('/sign-out', async (req, res, next) => {
  res.clearCookie('authorization');

  return res.status(200).json({ message: '로그아웃 되었습니다.' });
});

router.get('/users', authMiddleWare, async (req, res, next) => {
  const { userId } = req.user;

  const user = await prisma.users.findFirst({
    where: { userId: +userId },
    select: {
      userId: true,
      email: true,
      createdAt: true,
      updatedAt: true,
    },
  });
  return res.status(200).json({ data: user });
});

export default router;
