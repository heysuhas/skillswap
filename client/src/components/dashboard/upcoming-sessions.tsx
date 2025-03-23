import { useQuery } from "@tanstack/react-query";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Calendar, Clock, User } from "lucide-react";
import { format } from "date-fns";
import { useLocation } from "wouter";

export default function UpcomingSessions() {
  const [location, navigate] = useLocation();

  const { data: upcomingSessions, isLoading } = useQuery({
    queryKey: ['/api/sessions/upcoming'],
  });

  const handleViewCalendar = () => {
    navigate('/sessions');
  };

  const formatSessionTime = (startTime: string, endTime: string) => {
    const start = new Date(startTime);
    const end = new Date(endTime);
    
    const isToday = new Date().toDateString() === start.toDateString();
    const dateText = isToday ? 'Today' : format(start, 'MMM d');
    
    return `${dateText}, ${format(start, 'h:mm a')} - ${format(end, 'h:mm a')}`;
  };

  if (isLoading) {
    return (
      <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-slate-800">Upcoming Sessions</h2>
          <Button variant="link" size="sm" disabled>View Calendar</Button>
        </div>
        
        <div className="space-y-3">
          {Array.from({ length: 2 }).map((_, i) => (
            <div key={i} className="p-3 border border-slate-200 rounded-md">
              <div className="flex items-start">
                <Skeleton className="w-10 h-10 rounded" />
                <div className="ml-3">
                  <Skeleton className="h-4 w-32" />
                  <Skeleton className="h-3 w-40 mt-1" />
                  <Skeleton className="h-3 w-24 mt-1" />
                </div>
              </div>
              <div className="mt-2 flex space-x-2">
                <Skeleton className="h-8 flex-1 rounded" />
                <Skeleton className="h-8 flex-1 rounded" />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-slate-800">Upcoming Sessions</h2>
        <Button 
          variant="link" 
          size="sm"
          onClick={handleViewCalendar}
        >
          View Calendar
        </Button>
      </div>
      
      {!upcomingSessions || upcomingSessions.length === 0 ? (
        <div className="p-6 text-center">
          <Calendar className="h-12 w-12 text-slate-300 mx-auto mb-3" />
          <p className="text-slate-500">No upcoming sessions scheduled.</p>
          <Button 
            variant="outline" 
            size="sm" 
            onClick={handleViewCalendar}
            className="mt-2"
          >
            Schedule a Session
          </Button>
        </div>
      ) : (
        <div className="space-y-3">
          {upcomingSessions.map((session: any) => (
            <div key={session.id} className="p-3 border border-slate-200 rounded-md hover:bg-slate-50">
              <div className="flex items-start">
                <div className="flex-shrink-0 w-10 h-10 rounded bg-primary-100 flex items-center justify-center text-primary-600">
                  <Calendar className="h-5 w-5" />
                </div>
                <div className="ml-3">
                  <p className="text-sm font-medium text-slate-800">{session.title}</p>
                  <p className="text-xs text-slate-500">
                    <Clock className="inline-block h-3 w-3 mr-1" />
                    <span>{formatSessionTime(session.startTime, session.endTime)}</span>
                  </p>
                  <p className="text-xs text-slate-500">
                    <User className="inline-block h-3 w-3 mr-1" />
                    <span>{session.match.user.username}</span>
                  </p>
                </div>
              </div>
              <div className="mt-2 flex space-x-2">
                <Button className="flex-1 h-8 text-xs">
                  Join Call
                </Button>
                <Button variant="outline" className="flex-1 h-8 text-xs">
                  Reschedule
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
