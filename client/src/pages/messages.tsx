import { useEffect, useState, useRef } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useAuth } from "@/hooks/use-auth";
import { useWebSocket } from "@/hooks/use-websocket";
import { useToast } from "@/hooks/use-toast";
import { useParams, useLocation } from "wouter";

// Layout components
import Sidebar from "@/components/layout/sidebar";
import MobileSidebar from "@/components/layout/mobile-sidebar";
import MobileNav from "@/components/layout/mobile-nav";

// UI components
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { format } from "date-fns";
import { 
  Send, 
  ChevronLeft, 
  CalendarPlus, 
  Users, 
  Image as ImageIcon, 
  Mic, 
  X, 
  Paperclip
} from "lucide-react";

export default function Messages() {
  const { id } = useParams<{ id?: string }>();
  const [_, navigate] = useLocation();
  const { user } = useAuth();
  const { toast } = useToast();
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState<any[]>([]);
  const scrollRef = useRef<HTMLDivElement>(null);

  // State for media file handling
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [mediaPreview, setMediaPreview] = useState<string | null>(null);
  const [isRecording, setIsRecording] = useState(false);
  const [recordingBlob, setRecordingBlob] = useState<Blob | null>(null);
  const [activeMessageType, setActiveMessageType] = useState<'text' | 'image' | 'voice'>('text');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<BlobPart[]>([]);

  // WebSocket connection
  const { sendMessage, isConnected } = useWebSocket({
    onMessage: (data) => {
      if (data.type === 'message' && data.message && data.message.matchId.toString() === id) {
        console.log('Received WebSocket message:', data);
        setMessages((prev) => {
          if (!prev.some(m => m.id === data.message.id)) {
            return [...prev, data.message];
          }
          return prev;
        });
      } else if (data.type === 'message_sent') {
        console.log('Message sent confirmation received:', data);
        queryClient.invalidateQueries({ queryKey: [`/api/matches/${id}/messages`] });
      }
    },
  });

  // Fetch matches
  const { data: matches, isLoading: isLoadingMatches } = useQuery({
    queryKey: ['/api/matches'],
  });

  // Fetch selected match
  const { data: match, isLoading: isLoadingMatch } = useQuery({
    queryKey: [`/api/matches/${id}`],
    enabled: !!id,
  });

  // Fetch messages for selected match
  const { data: messageData, isLoading: isLoadingMessages } = useQuery({
    queryKey: [`/api/matches/${id}/messages`],
    enabled: !!id,
  });

  // Send message mutation
  const sendMessageMutation = useMutation({
    mutationFn: async ({ 
      matchId, 
      content, 
      messageType = 'text',
      mediaUrl = null 
    }: { 
      matchId: string, 
      content: string,
      messageType?: string,
      mediaUrl?: string | null 
    }) => {
      console.log('Sending message via API:', { matchId, content, messageType, mediaUrl, userId: user?.id });
      const response = await apiRequest('POST', `/api/matches/${matchId}/messages`, { 
        content, 
        messageType, 
        mediaUrl,
        userId: user?.id
      });
      return await response.json();
    },
    onSuccess: (data) => {
      console.log('Message sent successfully via API, with data:', data);
      
      if (data && !messages.some((m: any) => m.id === data.id)) {
        setMessages((prev) => [...prev, {
          ...data,
          sender: {
            id: user?.id,
            username: user?.username
          }
        }]);
      }
      
      queryClient.invalidateQueries({ queryKey: [`/api/matches/${id}/messages`] });
    },
    onError: (error: any) => {
      console.error('Message error details:', error);
      toast({
        title: "Error",
        description: error.message || "Failed to send message",
        variant: "destructive",
      });
    }
  });

  // Update messages when data changes
  useEffect(() => {
    if (messageData) {
      console.log('Message data received from API:', messageData);
      
      const existingMessageIds = new Set(messages.map(m => m.id));
      const newMessages = messageData.filter(m => !existingMessageIds.has(m.id));
      
      if (newMessages.length > 0) {
        setMessages(prev => [...prev, ...newMessages]);
      } else if (messages.length === 0 && messageData.length > 0) {
        setMessages(messageData);
      }
    }
  }, [messageData, messages]);

  // Scroll to bottom when messages change
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  // Handle file selection
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    
    setSelectedFile(file);
    
    // Create preview URL
    const reader = new FileReader();
    reader.onloadend = () => {
      setMediaPreview(reader.result as string);
    };
    reader.readAsDataURL(file);
    
    // Switch to image mode
    setActiveMessageType('image');
  };
  
  // Cancel media upload/recording
  const cancelMedia = () => {
    setSelectedFile(null);
    setMediaPreview(null);
    setRecordingBlob(null);
    setActiveMessageType('text');
    
    // Reset file input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
    
    // Stop recording if in progress
    if (isRecording) {
      stopRecording();
    }
  };
  
  // Start voice recording
  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const mediaRecorder = new MediaRecorder(stream);
      mediaRecorderRef.current = mediaRecorder;
      audioChunksRef.current = [];
      
      mediaRecorder.ondataavailable = (e) => {
        if (e.data.size > 0) {
          audioChunksRef.current.push(e.data);
        }
      };
      
      mediaRecorder.onstop = () => {
        const audioBlob = new Blob(audioChunksRef.current, { type: 'audio/mp3' });
        setRecordingBlob(audioBlob);
        
        // Create preview URL
        const audioUrl = URL.createObjectURL(audioBlob);
        setMediaPreview(audioUrl);
        
        // Close stream tracks
        stream.getTracks().forEach(track => track.stop());
      };
      
      mediaRecorder.start();
      setIsRecording(true);
      setActiveMessageType('voice');
    } catch (error) {
      console.error('Error starting recording:', error);
      toast({
        title: "Error",
        description: "Could not access microphone. Please check permissions.",
        variant: "destructive",
      });
    }
  };
  
  // Stop voice recording
  const stopRecording = () => {
    if (mediaRecorderRef.current && isRecording) {
      mediaRecorderRef.current.stop();
      setIsRecording(false);
    }
  };
  
  // Upload file and return URL (mock implementation - in a real app this would upload to a server)
  const uploadFile = async (file: File | Blob): Promise<string> => {
    // In a real app, this would upload the file to a server/cloud storage
    // and return the URL. For this prototype, we'll create an object URL.
    return URL.createObjectURL(file);
  };
  
  // Handle sending a message (text, image, or voice)
  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!id) return;
    
    // Don't proceed if no content for the current message type
    if (
      (activeMessageType === 'text' && !message.trim()) ||
      (activeMessageType === 'image' && !selectedFile) ||
      (activeMessageType === 'voice' && !recordingBlob)
    ) {
      return;
    }
    
    try {
      let content = '';
      let mediaUrl = null;
      
      // Process based on message type
      if (activeMessageType === 'text') {
        content = message;
      } else if (activeMessageType === 'image' && selectedFile) {
        content = 'Sent an image';
        mediaUrl = await uploadFile(selectedFile);
      } else if (activeMessageType === 'voice' && recordingBlob) {
        content = 'Sent a voice message';
        mediaUrl = await uploadFile(recordingBlob);
      }
      
      console.log('Preparing to send message:', { content, matchId: id, type: activeMessageType });
      
      // Get the current message text before clearing it
      const messageToBeSent = content;
      
      // Reset state immediately to prevent double sends
      setMessage("");
      setSelectedFile(null);
      setMediaPreview(null);
      setRecordingBlob(null);
      
      // Send through API first to ensure it's saved
      const result = await sendMessageMutation.mutateAsync({ 
        matchId: id, 
        content: messageToBeSent,
        messageType: activeMessageType,
        mediaUrl
      });
      
      console.log('API message result:', result);
      
      // Only send WebSocket message if API call succeeded
      if (isConnected) {
        console.log('Sending message via WebSocket');
        sendMessage({
          type: 'message',
          matchId: parseInt(id),
          userId: user?.id,
          content: messageToBeSent,
          messageType: activeMessageType,
          mediaUrl
        });
      }
      
      // Reset message type after successful send
      setActiveMessageType('text');
      
      // Reset file input if it exists
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    } catch (error) {
      console.error('Error sending message:', error);
      toast({
        title: "Error",
        description: "Failed to send message. Please try again.",
        variant: "destructive",
      });
    }
  };

  // Format message time
  const formatMessageTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return format(date, 'h:mm a');
  };

  // Get accepted matches
  const getAcceptedMatches = () => {
    if (!matches) return [];
    return matches.filter((match: any) => match.status === 'accepted');
  };

  // Selected conversation or empty state
  const renderConversation = () => {
    if (!id) {
      return (
        <div className="flex-1 flex items-center justify-center bg-white border-l border-slate-200">
          <div className="text-center p-8">
            <Users className="h-12 w-12 text-slate-300 mx-auto mb-3" />
            <h3 className="text-lg font-medium text-slate-800">Select a conversation</h3>
            <p className="text-slate-500 mt-1">
              Choose a match from the left to start chatting
            </p>
          </div>
        </div>
      );
    }

    if (isLoadingMatch || isLoadingMessages) {
      return (
        <div className="flex-1 flex flex-col bg-white border-l border-slate-200">
          <div className="h-16 border-b border-slate-200 px-4 flex items-center">
            <div className="flex items-center">
              <Skeleton className="w-10 h-10 rounded-full" />
              <Skeleton className="h-4 w-32 ml-3" />
            </div>
          </div>
          <ScrollArea className="flex-1 p-4">
            <div className="space-y-4">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className={`flex ${i % 2 === 0 ? 'justify-end' : ''}`}>
                  <div className={`max-w-[70%] px-4 py-2 rounded-lg ${i % 2 === 0 ? 'bg-primary-100 text-primary-900' : 'bg-slate-100'}`}>
                    <Skeleton className="h-3 w-32" />
                    <Skeleton className="h-3 w-24 mt-1" />
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>
        </div>
      );
    }

    return (
      <div className="flex-1 flex flex-col bg-white border-l border-slate-200">
        {/* Chat header */}
        <div className="h-16 border-b border-slate-200 px-4 flex items-center justify-between">
          <div className="flex items-center">
            <button 
              className="md:hidden mr-2 text-slate-500"
              onClick={() => navigate('/messages')}
            >
              <ChevronLeft className="h-5 w-5" />
            </button>
            <div className="w-10 h-10 rounded-full bg-primary-100 flex items-center justify-center text-primary-600">
              {match?.user?.username?.charAt(0).toUpperCase()}
            </div>
            <div className="ml-3">
              <p className="font-medium text-slate-800">{match?.user?.username}</p>
            </div>
          </div>
          <Button 
            variant="ghost" 
            size="sm"
            onClick={() => navigate('/sessions')}
          >
            <CalendarPlus className="h-4 w-4 mr-1" />
            Schedule
          </Button>
        </div>
        
        {/* Chat messages */}
        <ScrollArea className="flex-1 p-4" ref={scrollRef}>
          {messages.length === 0 ? (
            <div className="h-full flex items-center justify-center">
              <div className="text-center p-6">
                <p className="text-slate-500">No messages yet</p>
                <p className="text-sm text-slate-400 mt-1">Send a message to start the conversation</p>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              {messages.map((msg: any) => {
                const isCurrentUser = msg.senderId === user?.id;
                const messageType = msg.messageType || 'text';
                
                return (
                  <div key={msg.id} className={`flex message-container ${isCurrentUser ? 'justify-end' : ''}`}>
                    {!isCurrentUser && (
                      <div className="w-8 h-8 rounded-full bg-primary-100 flex items-center justify-center text-primary-600 mr-2 shrink-0">
                        {msg.sender?.username?.charAt(0).toUpperCase()}
                      </div>
                    )}
                    <div>
                      <div className={`px-4 py-2 rounded-lg message-bubble ${
                        isCurrentUser 
                          ? 'bg-primary-100 text-primary-900' 
                          : 'bg-slate-100 text-slate-800'
                      }`}>
                        {messageType === 'text' && (
                          <p>{msg.content}</p>
                        )}
                        
                        {messageType === 'image' && msg.mediaUrl && (
                          <div className="space-y-2">
                            <p className="text-sm opacity-70">{msg.content}</p>
                            <div className="overflow-hidden rounded-md cursor-pointer transition-transform hover:scale-[0.98] shadow-sm hover:shadow">
                              <img 
                                src={msg.mediaUrl} 
                                alt="Image message" 
                                className="max-w-full max-h-[200px] object-contain"
                                onClick={() => {
                                  // Create modal or lightbox effect for image viewing
                                  window.open(msg.mediaUrl, '_blank', 'noopener,noreferrer');
                                }}
                              />
                              <div className="flex justify-end p-1.5 bg-slate-50 border-t border-slate-100">
                                <button 
                                  onClick={() => window.open(msg.mediaUrl, '_blank', 'noopener,noreferrer')}
                                  className="text-xs text-slate-500 hover:text-primary-600 flex items-center gap-1 p-1"
                                >
                                  <ImageIcon className="h-3 w-3" />
                                  View Full Image
                                </button>
                              </div>
                            </div>
                          </div>
                        )}
                        
                        {messageType === 'voice' && msg.mediaUrl && (
                          <div className="space-y-2">
                            <p className="text-sm opacity-70">{msg.content}</p>
                            <div className="bg-slate-100 p-2 rounded-md flex items-center shadow-sm">
                              <div className="w-8 h-8 rounded-full bg-primary-100 flex items-center justify-center text-primary-600 mr-2">
                                <Mic className="h-4 w-4" />
                              </div>
                              <audio 
                                controls 
                                src={msg.mediaUrl} 
                                className="flex-1 h-8 custom-audio-player"
                                controlsList="nodownload"
                              >
                                Your browser does not support audio playback
                              </audio>
                              <button 
                                onClick={() => window.open(msg.mediaUrl, '_blank', 'noopener,noreferrer')}
                                className="ml-2 p-1.5 text-slate-500 hover:text-primary-600 rounded-full hover:bg-slate-200"
                                title="Download voice message"
                              >
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                                  <polyline points="7 10 12 15 17 10" />
                                  <line x1="12" y1="15" x2="12" y2="3" />
                                </svg>
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                      <p className={`text-xs text-slate-400 mt-1 ${isCurrentUser ? 'text-right' : ''}`}>
                        {formatMessageTime(msg.createdAt)}
                      </p>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </ScrollArea>
        
        {/* Message input */}
        <div className="border-t border-slate-200 p-4">
          {/* Media preview */}
          {mediaPreview && (
            <div className="mb-3 p-3 bg-slate-50 rounded-md relative">
              <button 
                type="button" 
                onClick={cancelMedia} 
                className="absolute top-2 right-2 p-1 bg-slate-200 rounded-full hover:bg-slate-300"
              >
                <X className="h-4 w-4" />
              </button>
              
              {activeMessageType === 'image' && (
                <div className="flex justify-center">
                  <img 
                    src={mediaPreview} 
                    alt="Image preview" 
                    className="max-h-[150px] rounded-md object-contain"
                  />
                </div>
              )}
              
              {activeMessageType === 'voice' && (
                <div className="flex justify-center">
                  <audio controls src={mediaPreview} className="w-full">
                    Your browser does not support audio playback
                  </audio>
                </div>
              )}
            </div>
          )}
          
          {/* Recording in progress indicator */}
          {isRecording && (
            <div className="flex items-center gap-2 mb-3 p-2 bg-red-50 text-red-600 rounded-md">
              <div className="w-2 h-2 rounded-full bg-red-600 animate-pulse"></div>
              <p className="text-sm">Recording voice message...</p>
              <Button 
                type="button" 
                size="sm" 
                variant="outline" 
                className="ml-auto"
                onClick={stopRecording}
              >
                Stop
              </Button>
            </div>
          )}
          
          {/* Message input form */}
          <form onSubmit={handleSendMessage} className="flex flex-col space-y-2">
            <div className="flex items-center space-x-2">
              {activeMessageType === 'text' && (
                <Input
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  placeholder="Type your message..."
                  className="flex-1"
                  disabled={sendMessageMutation.isPending}
                />
              )}
              
              {/* Hidden file input for image uploads */}
              <input 
                type="file" 
                ref={fileInputRef}
                className="hidden" 
                accept="image/*"
                onChange={handleFileChange}
              />
              
              {/* Message type toggle buttons */}
              <div className="flex items-center gap-1">
                {!mediaPreview && !isRecording && (
                  <>
                    <Button 
                      type="button" 
                      size="icon" 
                      variant="ghost"
                      onClick={() => fileInputRef.current?.click()}
                      disabled={sendMessageMutation.isPending}
                    >
                      <ImageIcon className="h-4 w-4 text-slate-600" />
                    </Button>
                    
                    <Button 
                      type="button" 
                      size="icon" 
                      variant="ghost"
                      onClick={isRecording ? stopRecording : startRecording}
                      disabled={sendMessageMutation.isPending}
                    >
                      <Mic className={`h-4 w-4 ${isRecording ? 'text-red-500' : 'text-slate-600'}`} />
                    </Button>
                  </>
                )}
                
                <Button 
                  type="submit" 
                  size="icon" 
                  disabled={
                    (activeMessageType === 'text' && !message.trim()) || 
                    (activeMessageType === 'image' && !selectedFile) || 
                    (activeMessageType === 'voice' && !recordingBlob) || 
                    sendMessageMutation.isPending
                  }
                >
                  <Send className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </form>
        </div>
      </div>
    );
  };

  return (
    <div className="flex h-screen bg-slate-50">
      {/* Sidebar - Desktop only */}
      <Sidebar />
      
      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Mobile Header and Menu */}
        {!id && <MobileSidebar />}
        
        {/* Messages Content */}
        <div className="flex-1 flex overflow-hidden">
          {/* Conversations list - Hide on mobile when viewing a specific conversation */}
          <div className={`w-full md:w-72 lg:w-80 border-r border-slate-200 bg-white flex flex-col ${id ? 'hidden md:flex' : ''}`}>
            <div className="h-16 border-b border-slate-200 px-4 flex items-center">
              <h2 className="text-lg font-semibold text-slate-800">Messages</h2>
            </div>
            
            <ScrollArea className="flex-1">
              {isLoadingMatches ? (
                <div className="p-4 space-y-3">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <div key={i} className="flex items-start p-3 border border-slate-200 rounded-md">
                      <Skeleton className="w-10 h-10 rounded-full" />
                      <div className="ml-3 flex-1 min-w-0">
                        <Skeleton className="h-4 w-24" />
                        <Skeleton className="h-3 w-full mt-1" />
                      </div>
                    </div>
                  ))}
                </div>
              ) : getAcceptedMatches().length === 0 ? (
                <div className="p-8 text-center">
                  <Users className="h-10 w-10 text-slate-300 mx-auto mb-2" />
                  <p className="text-slate-500">No messages yet</p>
                  <p className="text-sm text-slate-400 mt-1">Start by connecting with matches</p>
                  <Button 
                    onClick={() => navigate('/matches')} 
                    className="mt-3"
                    size="sm"
                  >
                    Find Matches
                  </Button>
                </div>
              ) : (
                <div className="p-2">
                  {getAcceptedMatches().map((match: any) => (
                    <button
                      key={match.id}
                      className={`w-full flex items-start p-3 rounded-md text-left ${
                        id === match.id.toString() 
                          ? 'bg-primary-50' 
                          : 'hover:bg-slate-50'
                      }`}
                      onClick={() => navigate(`/messages/${match.id}`)}
                    >
                      <div className="w-10 h-10 rounded-full bg-primary-100 flex items-center justify-center text-primary-600">
                        {match.user.username.charAt(0).toUpperCase()}
                      </div>
                      <div className="ml-3 flex-1 min-w-0">
                        <p className="font-medium text-slate-800">{match.user.username}</p>
                        <p className="text-sm text-slate-500 truncate">
                          {match.latestMessage?.content || "No messages yet"}
                        </p>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </ScrollArea>
          </div>
          
          {/* Conversation view */}
          {renderConversation()}
        </div>
        
        {/* Mobile Bottom Navigation - Hide when viewing a specific conversation */}
        {!id && <MobileNav />}
      </main>
    </div>
  );
}
