import type { Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { storage } from "./storage";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import {
  loginSchema,
  registerSchema,
  insertUserSkillSchema,
  insertMessageSchema,
  insertSessionSchema,
  insertQuizAttemptSchema
} from "@shared/schema";
import { ZodError } from "zod";
import { fromZodError } from "zod-validation-error";

const JWT_SECRET = process.env.JWT_SECRET || "skillswap-secret-key";

// Active websocket connections
const clients = new Map<number, WebSocket>();

export async function registerRoutes(app: Express): Promise<Server> {
  const httpServer = createServer(app);

  // Set up WebSocket server
  const wss = new WebSocketServer({ server: httpServer, path: '/ws' });

  wss.on('connection', (ws, req) => {
    // Extract user ID from authorization header or query parameter
    const authToken = req.headers.authorization?.split(" ")[1] || 
                      new URLSearchParams(req.url?.split("?")[1] || "").get("token");
    
    if (!authToken) {
      ws.close(1008, "Authorization required");
      return;
    }

    let userId: number;
    try {
      const decoded = jwt.verify(authToken, JWT_SECRET) as { userId: number };
      userId = decoded.userId;
      
      // Store connection with user ID
      clients.set(userId, ws);
      
      // Handle messages
      ws.on('message', async (message) => {
        try {
          const data = JSON.parse(message.toString());
          
          if (data.type === 'message' && data.matchId && data.content) {
            // Create message object with optional media properties
            const messageData: any = {
              matchId: data.matchId,
              senderId: userId,
              content: data.content,
            };
            
            // Add message type and media URL if provided
            if (data.messageType) {
              messageData.messageType = data.messageType;
            }
            
            if (data.mediaUrl) {
              messageData.mediaUrl = data.mediaUrl;
            }
            
            // Save message to database
            const newMessage = await storage.createMessage(messageData);
            
            // Get match to find recipient
            const match = await storage.getMatch(data.matchId);
            if (match) {
              const recipientId = match.user1Id === userId ? match.user2Id : match.user1Id;
              const recipientWs = clients.get(recipientId);
              
              // Add sender information to message
              const sender = await storage.getUser(userId);
              
              // Forward message to recipient if online
              if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
                recipientWs.send(JSON.stringify({
                  type: 'message',
                  message: {
                    ...newMessage,
                    sender: {
                      id: sender?.id,
                      username: sender?.username
                    }
                  }
                }));
              }
              
              // Send confirmation to sender
              ws.send(JSON.stringify({
                type: 'message_sent',
                messageId: newMessage.id
              }));
            }
          }
        } catch (error) {
          console.error('WebSocket message error:', error);
        }
      });
      
      // Handle disconnection
      ws.on('close', () => {
        clients.delete(userId);
      });
      
    } catch (error) {
      ws.close(1008, "Invalid token");
    }
  });

  // Authentication routes
  app.post('/api/auth/register', async (req: Request, res: Response) => {
    try {
      const { email, username, password } = registerSchema.parse(req.body);
      
      // Check if user already exists
      const existingUser = await storage.getUserByEmail(email);
      if (existingUser) {
        return res.status(400).json({ message: "User already exists with this email" });
      }
      
      // Create new user
      const user = await storage.createUser({ email, username, password });
      
      // Generate JWT token
      const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
      
      res.status(201).json({
        user: {
          id: user.id,
          email: user.email,
          username: user.username
        },
        token
      });
    } catch (error) {
      if (error instanceof ZodError) {
        const validationError = fromZodError(error);
        return res.status(400).json({ message: validationError.message });
      }
      
      res.status(500).json({ message: "Failed to register user" });
    }
  });

  app.post('/api/auth/login', async (req: Request, res: Response) => {
    try {
      const { email, password } = loginSchema.parse(req.body);
      
      // Find user by email
      const user = await storage.getUserByEmail(email);
      if (!user) {
        return res.status(401).json({ message: "Invalid email or password" });
      }
      
      // Verify password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: "Invalid email or password" });
      }
      
      // Generate JWT token
      const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
      
      res.json({
        user: {
          id: user.id,
          email: user.email,
          username: user.username
        },
        token
      });
    } catch (error) {
      if (error instanceof ZodError) {
        const validationError = fromZodError(error);
        return res.status(400).json({ message: validationError.message });
      }
      
      res.status(500).json({ message: "Failed to log in" });
    }
  });

  // Middleware to verify JWT token
  const authenticate = (req: Request, res: Response, next: () => void) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ message: "Authorization header required" });
    }
    
    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "Bearer token required" });
    }
    
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as { userId: number };
      res.locals.userId = decoded.userId;
      next();
    } catch (error) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }
  };

  // User routes
  app.get('/api/user', authenticate, async (req: Request, res: Response) => {
    const userId = res.locals.userId;
    
    try {
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      res.json({
        id: user.id,
        email: user.email,
        username: user.username,
        profilePicture: user.profilePicture
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to get user data" });
    }
  });
  
  // Update user profile (currently only for profile picture)
  app.put('/api/user/profile', authenticate, async (req: Request, res: Response) => {
    try {
      const userId = res.locals.userId;
      const { profilePicture } = req.body;
      
      const updatedUser = await storage.updateUserProfile(userId, { profilePicture });
      
      if (!updatedUser) {
        return res.status(404).json({ message: "User not found" });
      }
      
      res.json({
        id: updatedUser.id,
        email: updatedUser.email,
        username: updatedUser.username,
        profilePicture: updatedUser.profilePicture
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to update profile" });
    }
  });

  // Skills routes
  app.get('/api/skills', async (req: Request, res: Response) => {
    try {
      const skills = await storage.getSkills();
      res.json(skills);
    } catch (error) {
      res.status(500).json({ message: "Failed to get skills" });
    }
  });

  // User Skills routes
  app.get('/api/user/skills', authenticate, async (req: Request, res: Response) => {
    const userId = res.locals.userId;
    
    try {
      const userSkills = await storage.getUserSkills(userId);
      res.json(userSkills);
    } catch (error) {
      res.status(500).json({ message: "Failed to get user skills" });
    }
  });

  app.get('/api/user/skills/teaching', authenticate, async (req: Request, res: Response) => {
    const userId = res.locals.userId;
    
    try {
      const teachingSkills = await storage.getUserTeachingSkills(userId);
      res.json(teachingSkills);
    } catch (error) {
      res.status(500).json({ message: "Failed to get teaching skills" });
    }
  });

  app.get('/api/user/skills/learning', authenticate, async (req: Request, res: Response) => {
    const userId = res.locals.userId;
    
    try {
      const learningSkills = await storage.getUserLearningSkills(userId);
      res.json(learningSkills);
    } catch (error) {
      res.status(500).json({ message: "Failed to get learning skills" });
    }
  });

  app.post('/api/user/skills', authenticate, async (req: Request, res: Response) => {
    const userId = res.locals.userId;
    
    try {
      const userSkillData = insertUserSkillSchema.parse({
        ...req.body,
        userId
      });
      
      const userSkill = await storage.createUserSkill(userSkillData);
      res.status(201).json(userSkill);
    } catch (error) {
      if (error instanceof ZodError) {
        const validationError = fromZodError(error);
        return res.status(400).json({ message: validationError.message });
      }
      
      res.status(500).json({ message: "Failed to add user skill" });
    }
  });

  app.put('/api/user/skills/:id', authenticate, async (req: Request, res: Response) => {
    const userId = res.locals.userId;
    const skillId = parseInt(req.params.id);
    
    try {
      const userSkill = await storage.updateUserSkill(skillId, req.body);
      if (!userSkill) {
        return res.status(404).json({ message: "User skill not found" });
      }
      
      if (userSkill.userId !== userId) {
        return res.status(403).json({ message: "Not authorized to update this skill" });
      }
      
      res.json(userSkill);
    } catch (error) {
      res.status(500).json({ message: "Failed to update user skill" });
    }
  });

  app.delete('/api/user/skills/:id', authenticate, async (req: Request, res: Response) => {
    const userId = res.locals.userId;
    const skillId = parseInt(req.params.id);
    
    try {
      const userSkill = await storage.updateUserSkill(skillId, {});
      if (!userSkill) {
        return res.status(404).json({ message: "User skill not found" });
      }
      
      if (userSkill.userId !== userId) {
        return res.status(403).json({ message: "Not authorized to delete this skill" });
      }
      
      await storage.deleteUserSkill(skillId);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Failed to delete user skill" });
    }
  });

  // Matches routes
  app.get('/api/matches', authenticate, async (req: Request, res: Response) => {
    const userId = res.locals.userId;
    
    try {
      const matches = await storage.getMatches(userId);
      res.json(matches);
    } catch (error) {
      res.status(500).json({ message: "Failed to get matches" });
    }
  });

  app.get('/api/matches/potential', authenticate, async (req: Request, res: Response) => {
    const userId = res.locals.userId;
    
    try {
      const potentialMatches = await storage.findPotentialMatches(userId);
      res.json(potentialMatches);
    } catch (error) {
      res.status(500).json({ message: "Failed to get potential matches" });
    }
  });

  app.put('/api/matches/:id/status', authenticate, async (req: Request, res: Response) => {
    const userId = res.locals.userId;
    const matchId = parseInt(req.params.id);
    const { status } = req.body;
    
    try {
      const match = await storage.getMatch(matchId);
      if (!match) {
        return res.status(404).json({ message: "Match not found" });
      }
      
      if (match.user1Id !== userId && match.user2Id !== userId) {
        return res.status(403).json({ message: "Not authorized to update this match" });
      }
      
      const updatedMatch = await storage.updateMatchStatus(matchId, status);
      res.json(updatedMatch);
    } catch (error) {
      res.status(500).json({ message: "Failed to update match status" });
    }
  });

  // Messages routes
  app.get('/api/matches/:id/messages', authenticate, async (req: Request, res: Response) => {
    const userId = req.body.userId;
    const matchId = parseInt(req.params.id);
    
    try {
      const match = await storage.getMatch(matchId);
      if (!match) {
        return res.status(404).json({ message: "Match not found" });
      }
      
      if (match.user1Id !== userId && match.user2Id !== userId) {
        return res.status(403).json({ message: "Not authorized to view these messages" });
      }
      
      const messages = await storage.getMessages(matchId);
      res.json(messages);
    } catch (error) {
      res.status(500).json({ message: "Failed to get messages" });
    }
  });

  app.post('/api/matches/:id/messages', authenticate, async (req: Request, res: Response) => {
    const userId = req.body.userId;
    const matchId = parseInt(req.params.id);
    
    try {
      const match = await storage.getMatch(matchId);
      if (!match) {
        return res.status(404).json({ message: "Match not found" });
      }
      
      if (match.user1Id !== userId && match.user2Id !== userId) {
        return res.status(403).json({ message: "Not authorized to send messages in this match" });
      }
      
      // Create message data object with optional fields
      const messageData: any = {
        matchId,
        senderId: userId,
        content: req.body.content
      };
      
      // Add message type if provided, otherwise default to "text"
      if (req.body.messageType) {
        messageData.messageType = req.body.messageType;
      }
      
      // Add media URL if provided
      if (req.body.mediaUrl) {
        messageData.mediaUrl = req.body.mediaUrl;
      }
      
      // Parse and validate with schema
      const validatedMessageData = insertMessageSchema.parse(messageData);
      
      const message = await storage.createMessage(validatedMessageData);
      
      // Get recipient's WebSocket connection
      const recipientId = match.user1Id === userId ? match.user2Id : match.user1Id;
      const recipientWs = clients.get(recipientId);
      
      // Add sender information to message
      const sender = await storage.getUser(userId);
      
      // Send message to recipient if they're online
      if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
        recipientWs.send(JSON.stringify({
          type: 'message',
          message: {
            ...message,
            sender: {
              id: sender?.id,
              username: sender?.username
            }
          }
        }));
      }
      
      res.status(201).json(message);
    } catch (error) {
      if (error instanceof ZodError) {
        const validationError = fromZodError(error);
        return res.status(400).json({ message: validationError.message });
      }
      
      res.status(500).json({ message: "Failed to send message" });
    }
  });

  // Sessions routes
  app.get('/api/sessions', authenticate, async (req: Request, res: Response) => {
    const userId = req.body.userId;
    
    try {
      const sessions = await storage.getSessions(userId);
      res.json(sessions);
    } catch (error) {
      res.status(500).json({ message: "Failed to get sessions" });
    }
  });

  app.get('/api/sessions/upcoming', authenticate, async (req: Request, res: Response) => {
    const userId = req.body.userId;
    
    try {
      const upcomingSessions = await storage.getUpcomingSessions(userId);
      res.json(upcomingSessions);
    } catch (error) {
      res.status(500).json({ message: "Failed to get upcoming sessions" });
    }
  });

  app.post('/api/sessions', authenticate, async (req: Request, res: Response) => {
    const userId = req.body.userId;
    
    try {
      const sessionData = insertSessionSchema.parse(req.body);
      
      // Verify user is part of the match
      const match = await storage.getMatch(sessionData.matchId);
      if (!match) {
        return res.status(404).json({ message: "Match not found" });
      }
      
      if (match.user1Id !== userId && match.user2Id !== userId) {
        return res.status(403).json({ message: "Not authorized to create session for this match" });
      }
      
      const session = await storage.createSession(sessionData);
      
      // Notify the other user about the new session
      const recipientId = match.user1Id === userId ? match.user2Id : match.user1Id;
      const recipientWs = clients.get(recipientId);
      
      if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
        recipientWs.send(JSON.stringify({
          type: 'session_created',
          session
        }));
      }
      
      res.status(201).json(session);
    } catch (error) {
      if (error instanceof ZodError) {
        const validationError = fromZodError(error);
        return res.status(400).json({ message: validationError.message });
      }
      
      res.status(500).json({ message: "Failed to create session" });
    }
  });

  app.put('/api/sessions/:id', authenticate, async (req: Request, res: Response) => {
    const userId = req.body.userId;
    const sessionId = parseInt(req.params.id);
    
    try {
      const session = await storage.updateSession(sessionId, {});
      if (!session) {
        return res.status(404).json({ message: "Session not found" });
      }
      
      // Verify user is part of the match
      const match = await storage.getMatch(session.matchId);
      if (!match) {
        return res.status(404).json({ message: "Match not found" });
      }
      
      if (match.user1Id !== userId && match.user2Id !== userId) {
        return res.status(403).json({ message: "Not authorized to update this session" });
      }
      
      const updatedSession = await storage.updateSession(sessionId, req.body);
      
      // Notify the other user about the updated session
      const recipientId = match.user1Id === userId ? match.user2Id : match.user1Id;
      const recipientWs = clients.get(recipientId);
      
      if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
        recipientWs.send(JSON.stringify({
          type: 'session_updated',
          session: updatedSession
        }));
      }
      
      res.json(updatedSession);
    } catch (error) {
      res.status(500).json({ message: "Failed to update session" });
    }
  });

  // Quiz routes
  app.get('/api/skills/:id/quizzes', authenticate, async (req: Request, res: Response) => {
    const skillId = parseInt(req.params.id);
    
    try {
      const quizzes = await storage.getQuizzesBySkill(skillId);
      res.json(quizzes);
    } catch (error) {
      res.status(500).json({ message: "Failed to get quizzes" });
    }
  });

  app.get('/api/quizzes/:id/questions', authenticate, async (req: Request, res: Response) => {
    const quizId = parseInt(req.params.id);
    
    try {
      const questions = await storage.getQuizQuestions(quizId);
      res.json(questions);
    } catch (error) {
      res.status(500).json({ message: "Failed to get quiz questions" });
    }
  });

  app.post('/api/quizzes/:id/attempt', authenticate, async (req: Request, res: Response) => {
    const userId = req.body.userId;
    const quizId = parseInt(req.params.id);
    
    try {
      const attemptData = insertQuizAttemptSchema.parse({
        userId,
        quizId,
        score: req.body.score,
        passed: req.body.passed
      });
      
      const attempt = await storage.createQuizAttempt(attemptData);
      res.status(201).json(attempt);
    } catch (error) {
      if (error instanceof ZodError) {
        const validationError = fromZodError(error);
        return res.status(400).json({ message: validationError.message });
      }
      
      res.status(500).json({ message: "Failed to record quiz attempt" });
    }
  });

  // Dashboard stats
  app.get('/api/user/stats', authenticate, async (req: Request, res: Response) => {
    const userId = req.body.userId;
    
    try {
      const teachingSkills = await storage.getUserTeachingSkills(userId);
      const learningSkills = await storage.getUserLearningSkills(userId);
      const matches = await storage.getMatches(userId);
      const sessions = await storage.getSessions(userId);
      
      res.json({
        teachingCount: teachingSkills.length,
        learningCount: learningSkills.length,
        matchesCount: matches.length,
        sessionsCount: sessions.length
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to get user stats" });
    }
  });

  return httpServer;
}
