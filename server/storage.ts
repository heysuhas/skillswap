import {
  User, InsertUser,
  Skill, InsertSkill,
  UserSkill, InsertUserSkill,
  Match, InsertMatch,
  Message, InsertMessage,
  Session, InsertSession,
  Quiz, InsertQuiz,
  QuizQuestion, InsertQuizQuestion,
  QuizAttempt, InsertQuizAttempt
} from "@shared/schema";
import bcrypt from "bcrypt";

export interface IStorage {
  // User methods
  getUser(id: number): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  updateUserProfile(id: number, updates: Partial<User>): Promise<User | undefined>;
  
  // Skills methods
  getSkills(): Promise<Skill[]>;
  getSkill(id: number): Promise<Skill | undefined>;
  createSkill(skill: InsertSkill): Promise<Skill>;
  
  // UserSkills methods
  getUserSkills(userId: number): Promise<(UserSkill & { skill: Skill })[]>;
  getUserTeachingSkills(userId: number): Promise<(UserSkill & { skill: Skill })[]>;
  getUserLearningSkills(userId: number): Promise<(UserSkill & { skill: Skill })[]>;
  createUserSkill(userSkill: InsertUserSkill): Promise<UserSkill>;
  updateUserSkill(id: number, updates: Partial<UserSkill>): Promise<UserSkill | undefined>;
  deleteUserSkill(id: number): Promise<boolean>;
  
  // Matches methods
  getMatches(userId: number): Promise<(Match & { user: User })[]>;
  getMatch(id: number): Promise<Match | undefined>;
  createMatch(match: InsertMatch): Promise<Match>;
  updateMatchStatus(id: number, status: string): Promise<Match | undefined>;
  findPotentialMatches(userId: number): Promise<(Match & { user: User, matchScore: number })[]>;
  
  // Messages methods
  getMessages(matchId: number): Promise<(Message & { sender: User })[]>;
  createMessage(message: InsertMessage): Promise<Message>;
  
  // Sessions methods
  getSessions(userId: number): Promise<(Session & { match: Match })[]>;
  getUpcomingSessions(userId: number): Promise<(Session & { match: Match & { user: User } })[]>;
  createSession(session: InsertSession): Promise<Session>;
  updateSession(id: number, updates: Partial<Session>): Promise<Session | undefined>;
  
  // Quiz methods
  getQuizzesBySkill(skillId: number): Promise<Quiz[]>;
  getQuizQuestions(quizId: number): Promise<QuizQuestion[]>;
  createQuizAttempt(attempt: InsertQuizAttempt): Promise<QuizAttempt>;
  getUserQuizAttempts(userId: number): Promise<QuizAttempt[]>;
}

export class MemStorage implements IStorage {
  private users: Map<number, User>;
  private skills: Map<number, Skill>;
  private userSkills: Map<number, UserSkill>;
  private matches: Map<number, Match>;
  private messages: Map<number, Message>;
  private sessions: Map<number, Session>;
  private quizzes: Map<number, Quiz>;
  private quizQuestions: Map<number, QuizQuestion>;
  private quizAttempts: Map<number, QuizAttempt>;
  
  private userIdCounter: number;
  private skillIdCounter: number;
  private userSkillIdCounter: number;
  private matchIdCounter: number;
  private messageIdCounter: number;
  private sessionIdCounter: number;
  private quizIdCounter: number;
  private quizQuestionIdCounter: number;
  private quizAttemptIdCounter: number;

  constructor() {
    this.users = new Map();
    this.skills = new Map();
    this.userSkills = new Map();
    this.matches = new Map();
    this.messages = new Map();
    this.sessions = new Map();
    this.quizzes = new Map();
    this.quizQuestions = new Map();
    this.quizAttempts = new Map();
    
    this.userIdCounter = 1;
    this.skillIdCounter = 1;
    this.userSkillIdCounter = 1;
    this.matchIdCounter = 1;
    this.messageIdCounter = 1;
    this.sessionIdCounter = 1;
    this.quizIdCounter = 1;
    this.quizQuestionIdCounter = 1;
    this.quizAttemptIdCounter = 1;
    
    // Initialize with some basic skills
    this.seedSkills();
    this.seedQuizzes();
  }

  private seedSkills() {
    const skills: InsertSkill[] = [
      { name: "JavaScript", description: "Programming language for web development", category: "Development" },
      { name: "React", description: "JavaScript library for building user interfaces", category: "Development" },
      { name: "Python", description: "Programming language for general purpose", category: "Development" },
      { name: "UI/UX Design", description: "User interface and experience design", category: "Design" },
      { name: "Digital Marketing", description: "Online marketing strategies", category: "Business" },
      { name: "Photography", description: "The art of capturing images", category: "Creative" },
      { name: "Data Analysis", description: "Processing and analyzing data", category: "Data" },
      { name: "Project Management", description: "Managing projects efficiently", category: "Business" }
    ];
    
    skills.forEach(skill => this.createSkill(skill));
  }

  private seedQuizzes() {
    // Map of skill names to their quiz questions
    const skillQuizzes: Record<string, { title: string, questions: Array<{ questionText: string, options: string[], correctAnswerIndex: number }> }> = {
      "JavaScript": {
        title: "JavaScript Verification",
        questions: [
          {
            questionText: "Which of the following is NOT a JavaScript data type?",
            options: [
              "String",
              "Boolean",
              "Integer",
              "Object"
            ],
            correctAnswerIndex: 2
          },
          {
            questionText: "What does the '===' operator do in JavaScript?",
            options: [
              "Assigns a value to a variable",
              "Compares values and types for equality",
              "Compares only values for equality",
              "Creates a new variable"
            ],
            correctAnswerIndex: 1
          },
          {
            questionText: "Which method would you use to add an element to the end of an array?",
            options: [
              "push()",
              "pop()",
              "shift()",
              "unshift()"
            ],
            correctAnswerIndex: 0
          }
        ]
      },
      "React": {
        title: "React Verification",
        questions: [
          {
            questionText: "What is React?",
            options: [
              "A server-side framework",
              "A JavaScript library for building user interfaces",
              "A database management system",
              "A full-stack framework"
            ],
            correctAnswerIndex: 1
          },
          {
            questionText: "What is JSX?",
            options: [
              "A JavaScript extension that allows HTML-like syntax in JavaScript",
              "A JavaScript database library",
              "A JavaScript debugging tool",
              "A CSS preprocessor"
            ],
            correctAnswerIndex: 0
          },
          {
            questionText: "What is the purpose of React hooks?",
            options: [
              "To connect to external APIs",
              "To add state and other React features to functional components",
              "To create class components",
              "To style React components"
            ],
            correctAnswerIndex: 1
          }
        ]
      },
      "Python": {
        title: "Python Verification",
        questions: [
          {
            questionText: "What is the correct way to define a function in Python?",
            options: [
              "function myFunction():",
              "def myFunction():",
              "create myFunction():",
              "func myFunction():"
            ],
            correctAnswerIndex: 1
          },
          {
            questionText: "Which of the following is NOT a valid Python data type?",
            options: [
              "List",
              "Dictionary",
              "String",
              "Character"
            ],
            correctAnswerIndex: 3
          },
          {
            questionText: "How do you create a list in Python?",
            options: [
              "list = (1, 2, 3)",
              "list = [1, 2, 3]",
              "list = {1, 2, 3}",
              "list = <1, 2, 3>"
            ],
            correctAnswerIndex: 1
          }
        ]
      },
      "UI/UX Design": {
        title: "UI/UX Design Verification",
        questions: [
          {
            questionText: "Which of the following best describes the purpose of a user persona?",
            options: [
              "A fictional representation of your target customer",
              "A technical specification document",
              "A diagram showing user journey flows",
              "A visual style guide for the interface"
            ],
            correctAnswerIndex: 0
          },
          {
            questionText: "What is the primary goal of user research?",
            options: [
              "To make the design process longer",
              "To understand user needs and behaviors",
              "To create more documentation",
              "To produce more wireframes"
            ],
            correctAnswerIndex: 1
          },
          {
            questionText: "What does 'UI' stand for in UI/UX?",
            options: [
              "User Investigation",
              "Universal Interface",
              "User Interface",
              "Usability Index"
            ],
            correctAnswerIndex: 2
          }
        ]
      },
      "Digital Marketing": {
        title: "Digital Marketing Verification",
        questions: [
          {
            questionText: "What does SEO stand for?",
            options: [
              "Social Engine Optimization",
              "Search Engine Optimization",
              "Social Engagement Opportunities",
              "Search Engagement Operations"
            ],
            correctAnswerIndex: 1
          },
          {
            questionText: "Which of the following is NOT a common digital marketing channel?",
            options: [
              "Email marketing",
              "Social media marketing",
              "Television advertising",
              "Content marketing"
            ],
            correctAnswerIndex: 2
          },
          {
            questionText: "What is a conversion rate?",
            options: [
              "The rate at which website visitors complete a desired action",
              "The rate at which emails get opened",
              "The rate at which currency is exchanged",
              "The rate at which ads are clicked"
            ],
            correctAnswerIndex: 0
          }
        ]
      },
      "Photography": {
        title: "Photography Verification",
        questions: [
          {
            questionText: "What does 'aperture' control in photography?",
            options: [
              "Image brightness",
              "Shutter speed",
              "Depth of field",
              "Image resolution"
            ],
            correctAnswerIndex: 2
          },
          {
            questionText: "What does ISO measure?",
            options: [
              "Camera lens quality",
              "Light sensitivity of the camera sensor",
              "Image size",
              "Shutter speed"
            ],
            correctAnswerIndex: 1
          },
          {
            questionText: "What is the 'rule of thirds' in photography?",
            options: [
              "A rule stating you should always take three photos of each subject",
              "A composition principle that divides an image into nine equal parts",
              "A rule stating you should use three different camera settings",
              "A principle requiring three light sources"
            ],
            correctAnswerIndex: 1
          }
        ]
      },
      "Data Analysis": {
        title: "Data Analysis Verification",
        questions: [
          {
            questionText: "What is the first step in the data analysis process?",
            options: [
              "Data visualization",
              "Data cleaning",
              "Data collection",
              "Data interpretation"
            ],
            correctAnswerIndex: 2
          },
          {
            questionText: "Which of the following is NOT a common data visualization type?",
            options: [
              "Bar chart",
              "Pie chart",
              "Scatter plot",
              "Triangle matrix"
            ],
            correctAnswerIndex: 3
          },
          {
            questionText: "What does 'ETL' stand for in data analysis?",
            options: [
              "Extract, Transform, Load",
              "Evaluate, Test, Launch",
              "Examine, Track, Limit",
              "Enterprise Technical Logic"
            ],
            correctAnswerIndex: 0
          }
        ]
      },
      "Project Management": {
        title: "Project Management Verification",
        questions: [
          {
            questionText: "What is a Gantt chart used for?",
            options: [
              "Tracking project expenses",
              "Illustrating a project schedule",
              "Managing team communication",
              "Analyzing project risks"
            ],
            correctAnswerIndex: 1
          },
          {
            questionText: "What does the acronym 'SMART' refer to in goal setting?",
            options: [
              "Simple, Meaningful, Actionable, Realistic, Timed",
              "Specific, Measurable, Achievable, Relevant, Time-bound",
              "Strategic, Manageable, Aligned, Reasonable, Tracked",
              "Systematic, Methodical, Adaptive, Rapid, Targeted"
            ],
            correctAnswerIndex: 1
          },
          {
            questionText: "Which of the following is NOT a project management methodology?",
            options: [
              "Agile",
              "Waterfall",
              "Kanban",
              "Recursive"
            ],
            correctAnswerIndex: 3
          }
        ]
      }
    };

    // Create quizzes for each skill
    Array.from(this.skills.values()).forEach(skill => {
      const quizData = skillQuizzes[skill.name];
      if (quizData) {
        const quizId = this.quizIdCounter++;
        const quiz: Quiz = {
          id: quizId,
          skillId: skill.id,
          title: quizData.title,
          passingScore: 7, // 70% passing score for all quizzes
        };
        this.quizzes.set(quizId, quiz);

        // Add questions to the quiz
        quizData.questions.forEach(q => {
          const questionId = this.quizQuestionIdCounter++;
          const question: QuizQuestion = {
            id: questionId,
            quizId,
            questionText: q.questionText,
            options: q.options,
            correctAnswerIndex: q.correctAnswerIndex
          };
          this.quizQuestions.set(questionId, question);
        });
      }
    });
  }

  // User methods
  async getUser(id: number): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(user => user.email === email);
  }

  async createUser(userData: InsertUser): Promise<User> {
    const id = this.userIdCounter++;
    const hashedPassword = await bcrypt.hash(userData.password, 10);
    const user: User = { 
      ...userData, 
      password: hashedPassword, 
      id, 
      createdAt: new Date(),
      profilePicture: userData.profilePicture || null
    };
    this.users.set(id, user);
    return user;
  }
  
  async updateUserProfile(id: number, updates: Partial<User>): Promise<User | undefined> {
    const user = this.users.get(id);
    if (!user) return undefined;
    
    const updatedUser: User = {
      ...user,
      ...updates,
      // Don't allow these fields to be updated via this method
      id: user.id,
      email: user.email,
      createdAt: user.createdAt
    };
    
    this.users.set(id, updatedUser);
    return updatedUser;
  }

  // Skills methods
  async getSkills(): Promise<Skill[]> {
    return Array.from(this.skills.values());
  }

  async getSkill(id: number): Promise<Skill | undefined> {
    return this.skills.get(id);
  }

  async createSkill(skillData: InsertSkill): Promise<Skill> {
    const id = this.skillIdCounter++;
    const skill: Skill = { ...skillData, id };
    this.skills.set(id, skill);
    return skill;
  }

  // UserSkills methods
  async getUserSkills(userId: number): Promise<(UserSkill & { skill: Skill })[]> {
    return Array.from(this.userSkills.values())
      .filter(userSkill => userSkill.userId === userId)
      .map(userSkill => {
        const skill = this.skills.get(userSkill.skillId);
        return { ...userSkill, skill: skill! };
      });
  }

  async getUserTeachingSkills(userId: number): Promise<(UserSkill & { skill: Skill })[]> {
    return (await this.getUserSkills(userId)).filter(userSkill => userSkill.isTeaching);
  }

  async getUserLearningSkills(userId: number): Promise<(UserSkill & { skill: Skill })[]> {
    return (await this.getUserSkills(userId)).filter(userSkill => !userSkill.isTeaching);
  }

  async createUserSkill(userSkillData: InsertUserSkill): Promise<UserSkill> {
    const id = this.userSkillIdCounter++;
    const userSkill: UserSkill = { ...userSkillData, id };
    this.userSkills.set(id, userSkill);
    return userSkill;
  }

  async updateUserSkill(id: number, updates: Partial<UserSkill>): Promise<UserSkill | undefined> {
    const userSkill = this.userSkills.get(id);
    if (!userSkill) return undefined;
    
    const updatedUserSkill = { ...userSkill, ...updates };
    this.userSkills.set(id, updatedUserSkill);
    return updatedUserSkill;
  }

  async deleteUserSkill(id: number): Promise<boolean> {
    return this.userSkills.delete(id);
  }

  // Matches methods
  async getMatches(userId: number): Promise<(Match & { user: User })[]> {
    return Array.from(this.matches.values())
      .filter(match => match.user1Id === userId || match.user2Id === userId)
      .map(match => {
        const otherUserId = match.user1Id === userId ? match.user2Id : match.user1Id;
        const user = this.users.get(otherUserId)!;
        return { ...match, user };
      });
  }

  async getMatch(id: number): Promise<Match | undefined> {
    return this.matches.get(id);
  }

  async createMatch(matchData: InsertMatch): Promise<Match> {
    const id = this.matchIdCounter++;
    const match: Match = { ...matchData, id, createdAt: new Date() };
    this.matches.set(id, match);
    return match;
  }

  async updateMatchStatus(id: number, status: string): Promise<Match | undefined> {
    const match = this.matches.get(id);
    if (!match) return undefined;
    
    const updatedMatch = { ...match, status };
    this.matches.set(id, updatedMatch);
    return updatedMatch;
  }

  async findPotentialMatches(userId: number): Promise<(Match & { user: User, matchScore: number })[]> {
    const user = await this.getUser(userId);
    if (!user) return [];
    
    // Get this user's teaching and learning skills
    const userTeachingSkills = await this.getUserTeachingSkills(userId);
    const userLearningSkills = await this.getUserLearningSkills(userId);
    
    const potentialMatches: (Match & { user: User, matchScore: number })[] = [];
    
    // Find all users who are not this user
    const otherUsers = Array.from(this.users.values()).filter(u => u.id !== userId);
    
    for (const otherUser of otherUsers) {
      // Get other user's teaching and learning skills
      const otherTeachingSkills = await this.getUserTeachingSkills(otherUser.id);
      const otherLearningSkills = await this.getUserLearningSkills(otherUser.id);
      
      // Check for skill matches
      let matchScore = 0;
      
      // Check if user's teaching skills match other's learning skills
      for (const teaching of userTeachingSkills) {
        if (otherLearningSkills.some(learning => learning.skillId === teaching.skillId)) {
          matchScore += 1;
        }
      }
      
      // Check if user's learning skills match other's teaching skills
      for (const learning of userLearningSkills) {
        if (otherTeachingSkills.some(teaching => teaching.skillId === learning.skillId)) {
          matchScore += 1;
        }
      }
      
      // If there's at least one match
      if (matchScore > 0) {
        const totalPossibleMatches = userTeachingSkills.length + userLearningSkills.length;
        const normalizedScore = Math.round((matchScore / totalPossibleMatches) * 100);
        
        // Check if a match already exists
        const existingMatch = Array.from(this.matches.values()).find(
          m => (m.user1Id === userId && m.user2Id === otherUser.id) || 
               (m.user1Id === otherUser.id && m.user2Id === userId)
        );
        
        if (!existingMatch) {
          // Create a new potential match
          const matchId = this.matchIdCounter++;
          const match: Match = {
            id: matchId,
            user1Id: userId,
            user2Id: otherUser.id,
            matchScore: normalizedScore,
            status: "pending",
            createdAt: new Date()
          };
          
          this.matches.set(matchId, match);
          potentialMatches.push({ ...match, user: otherUser, matchScore: normalizedScore });
        } else if (existingMatch.status === "pending") {
          potentialMatches.push({ ...existingMatch, user: otherUser, matchScore: normalizedScore });
        }
      }
    }
    
    // Sort by match score (highest first)
    return potentialMatches.sort((a, b) => b.matchScore - a.matchScore);
  }

  // Messages methods
  async getMessages(matchId: number): Promise<(Message & { sender: User })[]> {
    return Array.from(this.messages.values())
      .filter(message => message.matchId === matchId)
      .map(message => {
        const sender = this.users.get(message.senderId)!;
        return { ...message, sender };
      })
      .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
  }

  async createMessage(messageData: InsertMessage): Promise<Message> {
    const id = this.messageIdCounter++;
    
    // Set default message type to "text" if not provided
    const messageType = messageData.messageType || "text";
    
    // Create message with proper types
    const message: Message = { 
      ...messageData,
      id, 
      createdAt: new Date(),
      messageType,
      mediaUrl: messageData.mediaUrl || null
    };
    
    this.messages.set(id, message);
    return message;
  }

  // Sessions methods
  async getSessions(userId: number): Promise<(Session & { match: Match })[]> {
    const userMatches = await this.getMatches(userId);
    const matchIds = userMatches.map(match => match.id);
    
    return Array.from(this.sessions.values())
      .filter(session => matchIds.includes(session.matchId))
      .map(session => {
        const match = this.matches.get(session.matchId)!;
        return { ...session, match };
      });
  }

  async getUpcomingSessions(userId: number): Promise<(Session & { match: Match & { user: User } })[]> {
    const now = new Date();
    const sessions = await this.getSessions(userId);
    
    return sessions
      .filter(session => session.startTime > now && session.status === "scheduled")
      .map(session => {
        const otherUserId = session.match.user1Id === userId ? session.match.user2Id : session.match.user1Id;
        const user = this.users.get(otherUserId)!;
        return { 
          ...session, 
          match: { ...session.match, user } 
        };
      })
      .sort((a, b) => a.startTime.getTime() - b.startTime.getTime());
  }

  async createSession(sessionData: InsertSession): Promise<Session> {
    const id = this.sessionIdCounter++;
    const session: Session = { ...sessionData, id, createdAt: new Date() };
    this.sessions.set(id, session);
    return session;
  }

  async updateSession(id: number, updates: Partial<Session>): Promise<Session | undefined> {
    const session = this.sessions.get(id);
    if (!session) return undefined;
    
    const updatedSession = { ...session, ...updates };
    this.sessions.set(id, updatedSession);
    return updatedSession;
  }

  // Quiz methods
  async getQuizzesBySkill(skillId: number): Promise<Quiz[]> {
    return Array.from(this.quizzes.values())
      .filter(quiz => quiz.skillId === skillId);
  }

  async getQuizQuestions(quizId: number): Promise<QuizQuestion[]> {
    return Array.from(this.quizQuestions.values())
      .filter(question => question.quizId === quizId);
  }

  async createQuizAttempt(attemptData: InsertQuizAttempt): Promise<QuizAttempt> {
    const id = this.quizAttemptIdCounter++;
    const attempt: QuizAttempt = { ...attemptData, id, attemptedAt: new Date() };
    this.quizAttempts.set(id, attempt);
    
    // If the user passed the quiz, update the verification status of their skill
    if (attempt.passed) {
      const quiz = this.quizzes.get(attempt.quizId);
      if (quiz) {
        const userSkill = Array.from(this.userSkills.values()).find(
          us => us.userId === attempt.userId && us.skillId === quiz.skillId && us.isTeaching
        );
        
        if (userSkill) {
          this.updateUserSkill(userSkill.id, { isVerified: true });
        }
      }
    }
    
    return attempt;
  }

  async getUserQuizAttempts(userId: number): Promise<QuizAttempt[]> {
    return Array.from(this.quizAttempts.values())
      .filter(attempt => attempt.userId === userId);
  }
}

export const storage = new MemStorage();
