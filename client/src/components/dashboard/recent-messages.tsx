import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { MessageSquare } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { useLocation } from "wouter";

export default function RecentMessages() {
  const [location, navigate] = useLocation();

  const { data: matches, isLoading } = useQuery({
    queryKey: ['/api/matches'],
  });

  // Get the most recent message for each match
  const getRecentMessages = () => {
    if (!matches) return [];
    
    return matches
      .filter((match: any) => match.status === 'accepted' && match.latestMessage)
      .sort((a: any, b: any) => {
        const dateA = new Date(a.latestMessage?.createdAt || 0);
        const dateB = new Date(b.latestMessage?.createdAt || 0);
        return dateB.getTime() - dateA.getTime();
      })
      .slice(0, 3);
  };

  const handleViewAll = () => {
    navigate('/messages');
  };

  const formatMessageTime = (timestamp: string) => {
    if (!timestamp) return '';
    return formatDistanceToNow(new Date(timestamp), { addSuffix: true });
  };

  if (isLoading) {
    return (
      <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-slate-800">Recent Messages</h2>
          <Button variant="link" size="sm" disabled>View All</Button>
        </div>
        
        <div className="space-y-3">
          {Array.from({ length: 2 }).map((_, i) => (
            <div key={i} className="flex items-start p-3 border border-slate-200 rounded-md">
              <Skeleton className="w-10 h-10 rounded-full" />
              <div className="ml-3 flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <Skeleton className="h-4 w-24" />
                  <Skeleton className="h-3 w-10" />
                </div>
                <Skeleton className="h-3 w-full mt-1" />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  const recentMessages = getRecentMessages();

  return (
    <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-slate-800">Recent Messages</h2>
        <Button 
          variant="link" 
          size="sm"
          onClick={handleViewAll}
        >
          View All
        </Button>
      </div>
      
      {recentMessages.length === 0 ? (
        <div className="p-6 text-center">
          <MessageSquare className="h-12 w-12 text-slate-300 mx-auto mb-3" />
          <p className="text-slate-500">No messages yet.</p>
          <p className="text-sm text-slate-400 mt-1">Connect with matches to start chatting!</p>
        </div>
      ) : (
        <div className="space-y-3">
          {recentMessages.map((match: any) => (
            <div 
              key={match.id} 
              className="flex items-start p-3 border border-slate-200 rounded-md hover:bg-slate-50 cursor-pointer"
              onClick={() => navigate(`/messages/${match.id}`)}
            >
              <div className="w-10 h-10 rounded-full bg-primary-100 flex items-center justify-center text-primary-600">
                {match.user.username.charAt(0).toUpperCase()}
              </div>
              <div className="ml-3 flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-medium text-slate-800">{match.user.username}</p>
                  <p className="text-xs text-slate-500">{formatMessageTime(match.latestMessage?.createdAt)}</p>
                </div>
                <p className="text-sm text-slate-600 truncate">
                  {match.latestMessage?.content || "No messages yet"}
                </p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
