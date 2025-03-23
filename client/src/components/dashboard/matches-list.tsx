import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { queryClient } from "@/lib/queryClient";
import { useLocation } from "wouter";

export default function MatchesList() {
  const [location, navigate] = useLocation();
  const { toast } = useToast();

  const { data: potentialMatches, isLoading } = useQuery({
    queryKey: ['/api/matches/potential'],
  });

  const connectMutation = useMutation({
    mutationFn: async (matchId: number) => {
      return await apiRequest('PUT', `/api/matches/${matchId}/status`, { status: 'accepted' });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/matches/potential'] });
      queryClient.invalidateQueries({ queryKey: ['/api/matches'] });
      toast({
        title: "Connection established!",
        description: "You can now start messaging with this user.",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to connect with this user",
        variant: "destructive",
      });
    }
  });

  const handleViewAll = () => {
    navigate('/matches');
  };

  if (isLoading) {
    return (
      <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-slate-800">Potential Matches</h2>
          <Button variant="outline" size="sm" disabled>See All</Button>
        </div>
        
        <div className="space-y-4">
          {Array.from({ length: 2 }).map((_, i) => (
            <div key={i} className="flex flex-col sm:flex-row sm:items-center p-4 border border-slate-200 rounded-lg">
              <div className="flex items-center">
                <Skeleton className="w-12 h-12 rounded-full" />
                <div className="ml-3">
                  <Skeleton className="h-4 w-24" />
                  <Skeleton className="h-3 w-32 mt-1" />
                </div>
              </div>
              <div className="mt-3 sm:mt-0 sm:ml-auto flex flex-col sm:flex-row sm:items-center gap-2">
                <Skeleton className="h-6 w-16 rounded-full" />
                <Skeleton className="h-6 w-32" />
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
        <h2 className="text-lg font-semibold text-slate-800">Potential Matches</h2>
        <Button 
          variant="outline" 
          size="sm"
          onClick={handleViewAll}
        >
          See All
        </Button>
      </div>
      
      {!potentialMatches || potentialMatches.length === 0 ? (
        <div className="p-8 text-center">
          <Users className="h-12 w-12 text-slate-300 mx-auto mb-3" />
          <p className="text-slate-500">No potential matches found yet.</p>
          <p className="text-sm text-slate-400 mt-1">Try adding more skills to find matches!</p>
        </div>
      ) : (
        <div className="space-y-4">
          {potentialMatches.slice(0, 3).map((match: any) => (
            <div key={match.id} className="flex flex-col sm:flex-row sm:items-center p-4 border border-slate-200 rounded-lg hover:bg-slate-50">
              <div className="flex items-center">
                <div className="w-12 h-12 rounded-full bg-primary-100 flex items-center justify-center text-primary-600">
                  {match.user.username.charAt(0).toUpperCase()}
                </div>
                <div className="ml-3">
                  <p className="text-sm font-medium text-slate-800">{match.user.username}</p>
                  <p className="text-xs text-slate-500">{match.user.email}</p>
                </div>
              </div>
              
              <div className="mt-3 sm:mt-0 sm:ml-auto flex flex-col sm:flex-row sm:items-center gap-2">
                <div className="px-2 py-1 bg-primary-50 text-primary-700 text-xs font-medium rounded-full">
                  <span className="font-semibold">{match.matchScore}%</span> Match
                </div>
                
                <Button
                  size="sm"
                  onClick={() => connectMutation.mutate(match.id)}
                  disabled={connectMutation.isPending}
                >
                  Connect
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
