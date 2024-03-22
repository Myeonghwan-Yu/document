import express from 'express';
import { prisma } from '../models/index.js';
import authMiddleWare from '../middlewares/need-signin.middleware.js';

const router = express.Router();

router.get('/posts', async (req, res, next) => {
  try {
    const { orderKey, orderValue } = req.query;

    const posts = await prisma.documents.findMany({
      select: {
        postId: true,
        title: true,
        content: true,
        status: true,
        createdAt: true,
        user: {
          select: {
            email: true,
          },
        },
      },
      orderBy: {
        [orderKey || 'createdAt']:
          orderValue && orderValue.toLowerCase() === 'desc' ? 'desc' : 'asc',
      },
    });

    return res.status(200).json({ data: posts });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: '에러가 발생했습니다.' });
  }
});

// 1. 게시글을 작성하려는 클라이언트가 로그인된 사용자인지 검증합니다.
// 2. 게시글 생성을 위한 `title`, `content`를 **body**로 전달받습니다.
// 3. **Posts** 테이블에 게시글을 생성합니다.
router.post('/posts', authMiddleWare, async (req, res, next) => {
  const { title, content } = req.body;
  const { userId } = req.user;

  try {
    // 중복 체크 없이 문서 생성
    const post = await prisma.documents.create({
      data: {
        userId: +userId,
        title: title,
        content: content,
      },
    });

    return res.status(200).json({ data: post });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: '에러가 발생했습니다.' });
  }
});

router.get('/posts/:postId', async (req, res, next) => {
  try {
    const { postId } = req.params;

    const document = await prisma.documents.findUnique({
      where: {
        postId: +postId,
      },
      select: {
        postId: true,
        title: true,
        content: true,
        status: true,
        createdAt: true,
        user: {
          select: {
            email: true,
          },
        },
      },
    });

    if (!document) {
      return res.status(404).json({ message: '이력서를 찾을 수 없습니다.' });
    }

    return res.status(200).json({ data: document });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: '에러가 발생했습니다.' });
  }
});

router.patch('/posts/:postId', authMiddleWare, async (req, res, next) => {
  try {
    const { postId } = req.params;
    const { title, content, status } = req.body;
    const { userId, isAdmin } = req.user;

    const existingPost = await prisma.documents.findFirst({
      where: {
        postId: +postId,
      },
    });

    if (!existingPost) {
      return res
        .status(404)
        .json({ message: '이력서 조회에 실패하였습니다..' });
    }
    if (!isAdmin && existingPost.userId !== +userId) {
      return res
        .status(403)
        .json({ message: '본인이 작성한 이력서가 아닙니다.' });
    }

    const updatedPost = await prisma.documents.update({
      where: {
        postId: existingPost.postId,
      },
      data: {
        title: title || existingPost.title,
        content: content || existingPost.content,
        status: status || existingPost.status,
      },
    });

    return res.status(200).json({ data: updatedPost });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: '에러가 발생했습니다.' });
  }
});

router.delete('/posts/:postId', authMiddleWare, async (req, res, next) => {
  try {
    const { postId } = req.params;
    const existingPost = await prisma.documents.findFirst({
      where: {
        postId: +postId,
      },
    });

    if (!existingPost) {
      return res
        .status(404)
        .json({ message: '이력서 조회에 실패하였습니다..' });
    }

    const { userId, isAdmin } = req.user;

    if (!isAdmin && existingPost.userId !== +userId) {
      return res
        .status(403)
        .json({ message: '본인이 작성한 이력서가 아닙니다.' });
    }

    await prisma.documents.delete({
      where: {
        postId: +postId,
      },
    });

    return res
      .status(200)
      .json({ message: '이력서가 성공적으로 삭제되었습니다.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: '에러가 발생했습니다.' });
  }
});

export default router;
