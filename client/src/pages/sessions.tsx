import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { format, addHours } from "date-fns";

// Layout components
import Sidebar from "@/components/layout/sidebar";
import MobileSidebar from "@/components/layout/mobile-sidebar";
import MobileNav from "@/components/layout/mobile-nav";

// UI components
import { Button } from "@/components/ui/button";
import { Calendar } from "@/components/ui/calendar";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { 
  Form, 
  FormControl, 
  FormField, 
  FormItem, 
  FormLabel, 
  FormMessage 
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Calendar as CalendarIcon, Clock, User, Video, Plus, CalendarDays, Loader2 } from "lucide-react";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";

// Form schema for creating a session
const sessionFormSchema = z.object({
  matchId: z.string().min(1, "Please select a match"),
  title: z.string().min(3, "Title must be at least 3 characters"),
  description: z.string().optional(),
  date: z.date({
    required_error: "Please select a date",
  }),
  startTime: z.string().min(1, "Please select a start time"),
  duration: z.string().min(1, "Please select a duration"),
});

type SessionFormValues = z.infer<typeof sessionFormSchema>;

export default function Sessions() {
  const { toast } = useToast();
  const [isCreateSessionOpen, setIsCreateSessionOpen] = useState(false);
  
  // Fetch user's sessions
  const { data: sessions, isLoading: isLoadingAllSessions } = useQuery({
    queryKey: ['/api/sessions'],
  });

  // Fetch user's upcoming sessions
  const { data: upcomingSessions, isLoading: isLoadingUpcoming } = useQuery({
    queryKey: ['/api/sessions/upcoming'],
  });
  
  // Fetch user's matches for session creation
  const { data: matches, isLoading: isLoadingMatches } = useQuery({
    queryKey: ['/api/matches'],
  });
  
  // Filter for accepted matches only
  const getAcceptedMatches = () => {
    if (!matches) return [];
    return matches.filter((match: any) => match.status === 'accepted');
  };
  
  // Session creation form
  const form = useForm<SessionFormValues>({
    resolver: zodResolver(sessionFormSchema),
    defaultValues: {
      matchId: "",
      title: "",
      description: "",
      date: new Date(),
      startTime: "09:00",
      duration: "60",
    },
  });
  
  // Create session mutation
  const createSessionMutation = useMutation({
    mutationFn: async (data: any) => {
      return await apiRequest('POST', '/api/sessions', data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/sessions'] });
      queryClient.invalidateQueries({ queryKey: ['/api/sessions/upcoming'] });
      
      setIsCreateSessionOpen(false);
      form.reset();
      
      toast({
        title: "Session scheduled",
        description: "Your learning session has been scheduled successfully.",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to schedule session",
        variant: "destructive",
      });
    }
  });
  
  // Form submission handler
  function onSubmit(values: SessionFormValues) {
    const { date, startTime, duration, ...rest } = values;
    
    // Parse time and create Date objects
    const [hours, minutes] = startTime.split(':').map(Number);
    const startDate = new Date(date);
    startDate.setHours(hours, minutes, 0, 0);
    
    // Calculate end time
    const endDate = addHours(startDate, Number(duration) / 60);
    
    // Convert dates to actual Date objects instead of ISO strings
    // This ensures the server receives them as Date objects as expected by the schema
    createSessionMutation.mutate({
      ...rest,
      matchId: parseInt(values.matchId),
      startTime: startDate,
      endTime: endDate,
      status: "scheduled",
    });
  }
  
  // Format session date/time
  const formatSessionDateTime = (startTime: string, endTime: string) => {
    const start = new Date(startTime);
    const end = new Date(endTime);
    return `${format(start, 'MMMM d, yyyy')} • ${format(start, 'h:mm a')} - ${format(end, 'h:mm a')}`;
  };
  
  // Render loading state
  const renderLoading = () => (
    <div className="space-y-4">
      {Array.from({ length: 3 }).map((_, i) => (
        <div key={i} className="p-4 border border-slate-200 rounded-lg bg-white">
          <div className="flex items-start">
            <Skeleton className="w-10 h-10 rounded" />
            <div className="ml-3 flex-1">
              <Skeleton className="h-5 w-48" />
              <Skeleton className="h-4 w-64 mt-2" />
              <Skeleton className="h-4 w-32 mt-1" />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
  
  // Render empty state
  const renderEmpty = (type: 'upcoming' | 'past' | 'all') => (
    <div className="flex flex-col items-center justify-center p-8 bg-white border border-slate-200 rounded-lg">
      <CalendarDays className="h-12 w-12 text-slate-300 mb-3" />
      <h3 className="text-lg font-medium text-slate-800">No sessions found</h3>
      <p className="text-slate-500 text-center mt-1">
        {type === 'upcoming' 
          ? "You don't have any upcoming sessions scheduled." 
          : type === 'past' 
            ? "You don't have any past sessions."
            : "You haven't scheduled any sessions yet."}
      </p>
      <Button 
        onClick={() => setIsCreateSessionOpen(true)}
        className="mt-4"
      >
        <Plus className="h-4 w-4 mr-1" />
        Schedule a Session
      </Button>
    </div>
  );
  
  return (
    <div className="flex h-screen bg-slate-50">
      {/* Sidebar - Desktop only */}
      <Sidebar />
      
      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Mobile Header and Menu */}
        <MobileSidebar />
        
        {/* Sessions Content */}
        <div className="flex-1 overflow-auto">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
            {/* Page Header */}
            <div className="flex items-center justify-between mb-6">
              <div>
                <h1 className="text-2xl font-semibold text-slate-800">Sessions</h1>
                <p className="text-sm text-slate-500">Schedule and manage your learning sessions</p>
              </div>
              <Button onClick={() => setIsCreateSessionOpen(true)}>
                <Plus className="h-4 w-4 mr-1" />
                New Session
              </Button>
            </div>
            
            <Tabs defaultValue="upcoming" className="space-y-6">
              <TabsList>
                <TabsTrigger value="upcoming">Upcoming</TabsTrigger>
                <TabsTrigger value="past">Past</TabsTrigger>
                <TabsTrigger value="all">All Sessions</TabsTrigger>
              </TabsList>
              
              {/* Upcoming Sessions Tab */}
              <TabsContent value="upcoming">
                {isLoadingUpcoming ? (
                  renderLoading()
                ) : !upcomingSessions || upcomingSessions.length === 0 ? (
                  renderEmpty('upcoming')
                ) : (
                  <div className="space-y-4">
                    {upcomingSessions.map((session: any) => (
                      <div key={session.id} className="p-4 border border-slate-200 rounded-lg bg-white hover:bg-slate-50">
                        <div className="flex items-start">
                          <div className="flex-shrink-0 w-10 h-10 rounded bg-primary-100 flex items-center justify-center text-primary-600">
                            <CalendarIcon className="h-5 w-5" />
                          </div>
                          <div className="ml-3">
                            <h3 className="font-medium text-slate-800">{session.title}</h3>
                            <p className="text-sm text-slate-600 mt-1">
                              <Clock className="inline-block h-3.5 w-3.5 mr-1" />
                              {formatSessionDateTime(session.startTime, session.endTime)}
                            </p>
                            <p className="text-sm text-slate-600">
                              <User className="inline-block h-3.5 w-3.5 mr-1" />
                              With {session.match.user.username}
                            </p>
                            {session.description && (
                              <p className="text-sm text-slate-600 mt-2">{session.description}</p>
                            )}
                          </div>
                        </div>
                        <div className="mt-4 flex space-x-3">
                          <Button className="w-full sm:w-auto">
                            <Video className="h-4 w-4 mr-1" />
                            Join Call
                          </Button>
                          <Button variant="outline" className="w-full sm:w-auto">
                            Reschedule
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </TabsContent>
              
              {/* Past Sessions Tab */}
              <TabsContent value="past">
                {isLoadingAllSessions ? (
                  renderLoading()
                ) : !sessions || !sessions.filter((s: any) => new Date(s.endTime) < new Date()).length ? (
                  renderEmpty('past')
                ) : (
                  <div className="space-y-4">
                    {sessions
                      .filter((s: any) => new Date(s.endTime) < new Date())
                      .map((session: any) => (
                        <div key={session.id} className="p-4 border border-slate-200 rounded-lg bg-white hover:bg-slate-50">
                          <div className="flex items-start">
                            <div className="flex-shrink-0 w-10 h-10 rounded bg-slate-100 flex items-center justify-center text-slate-600">
                              <CalendarIcon className="h-5 w-5" />
                            </div>
                            <div className="ml-3">
                              <div className="flex items-center">
                                <h3 className="font-medium text-slate-800">{session.title}</h3>
                                <span className="ml-2 px-2 py-0.5 text-xs bg-slate-100 text-slate-700 rounded">
                                  Completed
                                </span>
                              </div>
                              <p className="text-sm text-slate-600 mt-1">
                                <Clock className="inline-block h-3.5 w-3.5 mr-1" />
                                {formatSessionDateTime(session.startTime, session.endTime)}
                              </p>
                              <p className="text-sm text-slate-600">
                                <User className="inline-block h-3.5 w-3.5 mr-1" />
                                With {session.match.user.username}
                              </p>
                            </div>
                          </div>
                        </div>
                      ))}
                  </div>
                )}
              </TabsContent>
              
              {/* All Sessions Tab */}
              <TabsContent value="all">
                {isLoadingAllSessions ? (
                  renderLoading()
                ) : !sessions || !sessions.length ? (
                  renderEmpty('all')
                ) : (
                  <div className="space-y-4">
                    {sessions.map((session: any) => {
                      const isPast = new Date(session.endTime) < new Date();
                      
                      return (
                        <div key={session.id} className="p-4 border border-slate-200 rounded-lg bg-white hover:bg-slate-50">
                          <div className="flex items-start">
                            <div className={`flex-shrink-0 w-10 h-10 rounded flex items-center justify-center ${
                              isPast 
                                ? 'bg-slate-100 text-slate-600' 
                                : 'bg-primary-100 text-primary-600'
                            }`}>
                              <CalendarIcon className="h-5 w-5" />
                            </div>
                            <div className="ml-3">
                              <div className="flex items-center">
                                <h3 className="font-medium text-slate-800">{session.title}</h3>
                                <span className={`ml-2 px-2 py-0.5 text-xs rounded ${
                                  isPast 
                                    ? 'bg-slate-100 text-slate-700' 
                                    : 'bg-green-100 text-green-700'
                                }`}>
                                  {isPast ? 'Completed' : 'Upcoming'}
                                </span>
                              </div>
                              <p className="text-sm text-slate-600 mt-1">
                                <Clock className="inline-block h-3.5 w-3.5 mr-1" />
                                {formatSessionDateTime(session.startTime, session.endTime)}
                              </p>
                              <p className="text-sm text-slate-600">
                                <User className="inline-block h-3.5 w-3.5 mr-1" />
                                With {session.match.user.username}
                              </p>
                            </div>
                          </div>
                          {!isPast && (
                            <div className="mt-4 flex space-x-3">
                              <Button className="w-full sm:w-auto">
                                <Video className="h-4 w-4 mr-1" />
                                Join Call
                              </Button>
                              <Button variant="outline" className="w-full sm:w-auto">
                                Reschedule
                              </Button>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </TabsContent>
            </Tabs>
          </div>
        </div>
        
        {/* Create Session Dialog */}
        <Dialog open={isCreateSessionOpen} onOpenChange={setIsCreateSessionOpen}>
          <DialogContent className="sm:max-w-[550px]">
            <DialogHeader>
              <DialogTitle>Schedule a New Session</DialogTitle>
            </DialogHeader>
            
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                <FormField
                  control={form.control}
                  name="matchId"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Select a Match</FormLabel>
                      <Select 
                        onValueChange={field.onChange} 
                        defaultValue={field.value}
                      >
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Select a match" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {getAcceptedMatches().map((match: any) => (
                            <SelectItem key={match.id} value={match.id.toString()}>
                              {match.user.username}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <FormField
                  control={form.control}
                  name="title"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Session Title</FormLabel>
                      <FormControl>
                        <Input placeholder="e.g., JavaScript Basics" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <FormField
                  control={form.control}
                  name="description"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Description (Optional)</FormLabel>
                      <FormControl>
                        <Textarea 
                          placeholder="What will you cover in this session?" 
                          className="resize-none"
                          {...field} 
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <FormField
                    control={form.control}
                    name="date"
                    render={({ field }) => (
                      <FormItem className="flex flex-col">
                        <FormLabel>Date</FormLabel>
                        <Popover>
                          <PopoverTrigger asChild>
                            <FormControl>
                              <Button
                                variant="outline"
                                className="pl-3 text-left font-normal h-10"
                              >
                                {field.value ? (
                                  format(field.value, "PPP")
                                ) : (
                                  <span>Pick a date</span>
                                )}
                                <CalendarIcon className="ml-auto h-4 w-4 opacity-50" />
                              </Button>
                            </FormControl>
                          </PopoverTrigger>
                          <PopoverContent className="w-auto p-0" align="start">
                            <Calendar
                              mode="single"
                              selected={field.value}
                              onSelect={field.onChange}
                              disabled={(date) => date < new Date()}
                              initialFocus
                            />
                          </PopoverContent>
                        </Popover>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  
                  <FormField
                    control={form.control}
                    name="startTime"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Start Time</FormLabel>
                        <Select onValueChange={field.onChange} defaultValue={field.value}>
                          <FormControl>
                            <SelectTrigger>
                              <SelectValue placeholder="Select time" />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            {Array.from({ length: 24 }).map((_, hour) => (
                              [0, 30].map((minute) => {
                                const timeString = `${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}`;
                                const displayTime = format(new Date().setHours(hour, minute), 'h:mm a');
                                return (
                                  <SelectItem key={timeString} value={timeString}>
                                    {displayTime}
                                  </SelectItem>
                                );
                              })
                            ))}
                          </SelectContent>
                        </Select>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>
                
                <FormField
                  control={form.control}
                  name="duration"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Duration</FormLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Select duration" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="30">30 minutes</SelectItem>
                          <SelectItem value="60">1 hour</SelectItem>
                          <SelectItem value="90">1 hour 30 minutes</SelectItem>
                          <SelectItem value="120">2 hours</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <div className="flex justify-end space-x-2 pt-4">
                  <Button 
                    type="button" 
                    variant="outline" 
                    onClick={() => setIsCreateSessionOpen(false)}
                    disabled={createSessionMutation.isPending}
                  >
                    Cancel
                  </Button>
                  <Button 
                    type="submit"
                    disabled={createSessionMutation.isPending}
                  >
                    {createSessionMutation.isPending ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Scheduling...
                      </>
                    ) : (
                      "Schedule Session"
                    )}
                  </Button>
                </div>
              </form>
            </Form>
          </DialogContent>
        </Dialog>
        
        {/* Mobile Bottom Navigation */}
        <MobileNav />
      </main>
    </div>
  );
}
