import express from 'express';
import { prisma } from '../models/index.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import authMiddleWare from '../middlewares/need-signin.middleware.js';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();

const router = express.Router();

const transporter = nodemailer.createTransport({
  service: 'naver',
  auth: {
    user: 'shnu9990@naver.com',
    pass: '598635a1!',
  },
});

router.post('/sign-up', async (req, res) => {
  try {
    const { email, password, passCon, isAdmin } = req.body;

    const verificationCode = Math.random().toString(36).substr(2, 6);

    if (typeof isAdmin !== 'boolean') {
      return res
        .status(400)
        .json({ message: 'isAdmin 필드가 유효하지 않습니다.' });
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

    // 회원 정보 생성
    const hashedPassword = await bcrypt.hash(password, 10);
    await prisma.users.create({
      data: {
        email,
        password: hashedPassword,
        isAdmin,
        verificationCode,
      },
    });

    const mailOptions = {
      from: 'shnu9990@naver.com',
      to: email,
      subject: '회원가입을 위한 인증코드',
      text: `인증코드: ${verificationCode}`,
    };

    await transporter.sendMail(mailOptions);

    return res
      .status(201)
      .json({ message: '이메일로 인증코드를 전송했습니다.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: '에러가 발생했습니다.' });
  }
});

router.post('/verify-email', async (req, res) => {
  try {
    const { email, verificationCode } = req.body;

    const user = await prisma.users.findFirst({
      where: {
        email,
        verificationCode,
      },
    });

    if (!user) {
      return res.status(400).json({ message: '인증코드가 올바르지 않습니다.' });
    }

    // 이메일 인증이 완료되면 인증코드를 삭제합니다.
    await prisma.users.update({
      where: {
        email,
      },
      data: {
        verificationCode: null, // 인증코드를 null로 업데이트하여 삭제처리합니다.
      },
    });

    return res.status(200).json({ message: '이메일 인증이 완료되었습니다.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: '에러가 발생했습니다.' });
  }
});

router.post('/sign-in', async (req, res) => {
  try {
    const { email, password } = req.body;

    // 사용자가 존재하는지 확인
    const user = await prisma.users.findFirst({
      where: { email },
    });

    if (!user) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }

    // 이메일 인증 확인
    if (!user.verified) {
      return res.status(401).json({ message: '이메일 인증이 필요합니다.' });
    }

    // 비밀번호 일치 확인
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: '비밀번호가 일치하지 않습니다.' });
    }

    // 로그인 성공 시 토큰 생성 및 반환
    const accessToken = jwt.sign(
      { userId: user.userId },
      process.env.ACCESS_TOKEN_SECRET_KEY,
      { expiresIn: '1h' }
    );

    return res.status(200).json({ accessToken });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: '에러가 발생했습니다.' });
  }
});

router.post('/refresh-token', authMiddleWare, async (req, res) => {
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

router.post('/sign-out', authMiddleWare, async (req, res) => {
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');

  return res.status(200).json({ message: '로그아웃 되었습니다.' });
});

router.patch('/change-password', authMiddleWare, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const userId = req.user.userId;

    const user = await prisma.users.findUnique({
      where: { userId },
    });

    if (!user) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }

    const isPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isPasswordValid) {
      return res
        .status(401)
        .json({ message: '현재 비밀번호가 일치하지 않습니다.' });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    await prisma.users.update({
      where: { userId },
      data: { password: hashedNewPassword },
    });

    return res
      .status(200)
      .json({ message: '비밀번호가 성공적으로 변경되었습니다.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

router.delete('/delete-account', authMiddleWare, async (req, res) => {
  try {
    const { password } = req.body;
    const userId = req.user.userId;

    const user = await prisma.users.findUnique({
      where: { userId },
    });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: '비밀번호가 일치하지 않습니다.' });
    }

    await prisma.users.delete({
      where: { userId },
    });

    return res.status(200).json({ message: '회원 탈퇴가 완료되었습니다.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: '에러가 발생했습니다.' });
  }
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
      isAdmin: true,
    },
  });
  return res.status(200).json({ data: user });
});

export default router;
