import { pgTable, text, serial, integer, boolean, timestamp, uniqueIndex } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// User model
export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  email: text("email").notNull().unique(),
  username: text("username").notNull(),
  password: text("password").notNull(),
  profilePicture: text("profile_picture"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertUserSchema = createInsertSchema(users).omit({
  id: true,
  createdAt: true,
});

// Skills model
export const skills = pgTable("skills", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  category: text("category").notNull(),
});

export const insertSkillSchema = createInsertSchema(skills).omit({
  id: true,
});

// UserSkills model - for mapping skills to users
export const userSkills = pgTable("user_skills", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull().references(() => users.id),
  skillId: integer("skill_id").notNull().references(() => skills.id),
  proficiency: text("proficiency").notNull(), // 'beginner', 'intermediate', 'advanced'
  isTeaching: boolean("is_teaching").notNull(), // true if user is teaching, false if learning
  isVerified: boolean("is_verified").default(false),
});

export const insertUserSkillSchema = createInsertSchema(userSkills).omit({
  id: true,
});

// Matches model - for skill-based matches between users
export const matches = pgTable("matches", {
  id: serial("id").primaryKey(),
  user1Id: integer("user1_id").notNull().references(() => users.id),
  user2Id: integer("user2_id").notNull().references(() => users.id),
  matchScore: integer("match_score").notNull(), // Percentage match (0-100)
  status: text("status").notNull(), // 'pending', 'accepted', 'rejected'
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertMatchSchema = createInsertSchema(matches).omit({
  id: true,
  createdAt: true,
});

// Messages model - for chat between matched users
export const messages = pgTable("messages", {
  id: serial("id").primaryKey(),
  matchId: integer("match_id").notNull().references(() => matches.id),
  senderId: integer("sender_id").notNull().references(() => users.id),
  content: text("content").notNull(),
  messageType: text("message_type").notNull().default("text"), // "text", "image", "voice"
  mediaUrl: text("media_url"), // URL to image or voice file (if applicable)
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertMessageSchema = createInsertSchema(messages).omit({
  id: true,
  createdAt: true,
});

// Sessions model - for scheduled learning sessions
export const sessions = pgTable("sessions", {
  id: serial("id").primaryKey(),
  matchId: integer("match_id").notNull().references(() => matches.id),
  title: text("title").notNull(),
  description: text("description"),
  startTime: timestamp("start_time").notNull(),
  endTime: timestamp("end_time").notNull(),
  status: text("status").notNull(), // 'scheduled', 'completed', 'cancelled'
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertSessionSchema = createInsertSchema(sessions).omit({
  id: true,
  createdAt: true,
});

// Quiz model - for skill verification
export const quizzes = pgTable("quizzes", {
  id: serial("id").primaryKey(),
  skillId: integer("skill_id").notNull().references(() => skills.id),
  title: text("title").notNull(),
  passingScore: integer("passing_score").notNull(), // minimum score needed to pass
});

export const insertQuizSchema = createInsertSchema(quizzes).omit({
  id: true,
});

// Quiz questions
export const quizQuestions = pgTable("quiz_questions", {
  id: serial("id").primaryKey(),
  quizId: integer("quiz_id").notNull().references(() => quizzes.id),
  questionText: text("question_text").notNull(),
  options: text("options").array().notNull(), // Array of answer options
  correctAnswerIndex: integer("correct_answer_index").notNull(),
});

export const insertQuizQuestionSchema = createInsertSchema(quizQuestions).omit({
  id: true,
});

// Quiz attempts by users
export const quizAttempts = pgTable("quiz_attempts", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull().references(() => users.id),
  quizId: integer("quiz_id").notNull().references(() => quizzes.id),
  score: integer("score").notNull(),
  passed: boolean("passed").notNull(),
  attemptedAt: timestamp("attempted_at").defaultNow(),
});

export const insertQuizAttemptSchema = createInsertSchema(quizAttempts).omit({
  id: true,
  attemptedAt: true,
});

// Define types
export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;
export type Skill = typeof skills.$inferSelect;
export type InsertSkill = z.infer<typeof insertSkillSchema>;
export type UserSkill = typeof userSkills.$inferSelect;
export type InsertUserSkill = z.infer<typeof insertUserSkillSchema>;
export type Match = typeof matches.$inferSelect;
export type InsertMatch = z.infer<typeof insertMatchSchema>;
export type Message = typeof messages.$inferSelect;
export type InsertMessage = z.infer<typeof insertMessageSchema>;
export type Session = typeof sessions.$inferSelect;
export type InsertSession = z.infer<typeof insertSessionSchema>;
export type Quiz = typeof quizzes.$inferSelect;
export type InsertQuiz = z.infer<typeof insertQuizSchema>;
export type QuizQuestion = typeof quizQuestions.$inferSelect;
export type InsertQuizQuestion = z.infer<typeof insertQuizQuestionSchema>;
export type QuizAttempt = typeof quizAttempts.$inferSelect;
export type InsertQuizAttempt = z.infer<typeof insertQuizAttemptSchema>;

// Authentication schemas
export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

export const registerSchema = z.object({
  email: z.string().email(),
  username: z.string().min(3).max(30),
  password: z.string().min(6),
});

export type LoginCredentials = z.infer<typeof loginSchema>;
export type RegisterCredentials = z.infer<typeof registerSchema>;
