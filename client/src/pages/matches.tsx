import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useLocation } from "wouter";

// Layout components
import Sidebar from "@/components/layout/sidebar";
import MobileSidebar from "@/components/layout/mobile-sidebar";
import MobileNav from "@/components/layout/mobile-nav";

// UI components
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Users, MessageCircle, UserX, AlertCircle } from "lucide-react";

export default function Matches() {
  const [_, navigate] = useLocation();
  const { toast } = useToast();

  // Fetch existing matches
  const { data: matches, isLoading: isLoadingMatches } = useQuery({
    queryKey: ['/api/matches'],
  });

  // Fetch potential matches
  const { data: potentialMatches, isLoading: isLoadingPotential } = useQuery({
    queryKey: ['/api/matches/potential'],
  });

  // Accept match mutation
  const acceptMatchMutation = useMutation({
    mutationFn: async (matchId: number) => {
      return await apiRequest('PUT', `/api/matches/${matchId}/status`, { status: 'accepted' });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/matches'] });
      queryClient.invalidateQueries({ queryKey: ['/api/matches/potential'] });
      
      toast({
        title: "Match accepted",
        description: "You can now start messaging with this user.",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to accept match",
        variant: "destructive",
      });
    }
  });

  // Reject match mutation
  const rejectMatchMutation = useMutation({
    mutationFn: async (matchId: number) => {
      return await apiRequest('PUT', `/api/matches/${matchId}/status`, { status: 'rejected' });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/matches'] });
      queryClient.invalidateQueries({ queryKey: ['/api/matches/potential'] });
      
      toast({
        title: "Match rejected",
        description: "This user will no longer appear in your matches.",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to reject match",
        variant: "destructive",
      });
    }
  });

  // Get accepted matches
  const getAcceptedMatches = () => {
    if (!matches) return [];
    return matches.filter((match: any) => match.status === 'accepted');
  };

  // Get pending matches (received)
  const getPendingMatches = () => {
    if (!matches) return [];
    return matches.filter((match: any) => match.status === 'pending');
  };

  // Start chat with a match
  const startChat = (matchId: number) => {
    navigate(`/messages/${matchId}`);
  };

  // Render loading state
  const renderLoading = () => (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mt-4">
      {Array.from({ length: 3 }).map((_, i) => (
        <div key={i} className="p-4 border border-slate-200 rounded-lg bg-white">
          <div className="flex items-center">
            <Skeleton className="w-12 h-12 rounded-full" />
            <div className="ml-3">
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-3 w-24 mt-1" />
            </div>
          </div>
          <div className="mt-3">
            <Skeleton className="h-6 w-full" />
            <Skeleton className="h-6 w-full mt-2" />
          </div>
        </div>
      ))}
    </div>
  );

  // Render empty state
  const renderEmpty = (type: string) => (
    <div className="flex flex-col items-center justify-center p-8 mt-4 bg-white border border-slate-200 rounded-lg">
      {type === 'potential' ? (
        <>
          <Users className="h-12 w-12 text-slate-300 mb-3" />
          <h3 className="text-lg font-medium text-slate-800">No potential matches found</h3>
          <p className="text-slate-500 text-center mt-1">
            Try adding more skills to increase your chances of finding matches!
          </p>
        </>
      ) : type === 'accepted' ? (
        <>
          <MessageCircle className="h-12 w-12 text-slate-300 mb-3" />
          <h3 className="text-lg font-medium text-slate-800">No connections yet</h3>
          <p className="text-slate-500 text-center mt-1">
            Accept potential matches to start connecting with others!
          </p>
        </>
      ) : (
        <>
          <AlertCircle className="h-12 w-12 text-slate-300 mb-3" />
          <h3 className="text-lg font-medium text-slate-800">No pending matches</h3>
          <p className="text-slate-500 text-center mt-1">
            You don't have any pending match requests at the moment.
          </p>
        </>
      )}
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
        
        {/* Matches Content */}
        <div className="flex-1 overflow-auto">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
            {/* Page Header */}
            <div className="mb-6">
              <h1 className="text-2xl font-semibold text-slate-800">Matches</h1>
              <p className="text-sm text-slate-500">Find users with complementary skills to connect with</p>
            </div>
            
            <Tabs defaultValue="potential" className="space-y-6">
              <TabsList>
                <TabsTrigger value="potential">Potential Matches</TabsTrigger>
                <TabsTrigger value="connections">My Connections</TabsTrigger>
                <TabsTrigger value="pending">Pending</TabsTrigger>
              </TabsList>
              
              {/* Potential Matches Tab */}
              <TabsContent value="potential">
                <h2 className="text-lg font-medium text-slate-800 mb-3">Users you might want to connect with</h2>
                
                {isLoadingPotential ? (
                  renderLoading()
                ) : !potentialMatches || potentialMatches.length === 0 ? (
                  renderEmpty('potential')
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {potentialMatches.map((match: any) => (
                      <div key={match.id} className="p-4 border border-slate-200 rounded-lg bg-white hover:bg-slate-50">
                        <div className="flex items-center">
                          <div className="w-12 h-12 rounded-full bg-primary-100 flex items-center justify-center text-primary-600">
                            {match.user.username.charAt(0).toUpperCase()}
                          </div>
                          <div className="ml-3">
                            <p className="text-sm font-medium text-slate-800">{match.user.username}</p>
                            <p className="text-xs text-slate-500">{match.user.email}</p>
                          </div>
                          <Badge className="ml-auto">
                            {match.matchScore}% Match
                          </Badge>
                        </div>
                        
                        <div className="mt-4 grid grid-cols-2 gap-2">
                          <Button
                            variant="outline"
                            className="text-red-600 border-red-200 hover:bg-red-50"
                            onClick={() => rejectMatchMutation.mutate(match.id)}
                            disabled={rejectMatchMutation.isPending}
                          >
                            <UserX className="h-4 w-4 mr-1" />
                            Decline
                          </Button>
                          <Button
                            onClick={() => acceptMatchMutation.mutate(match.id)}
                            disabled={acceptMatchMutation.isPending}
                          >
                            <Users className="h-4 w-4 mr-1" />
                            Connect
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </TabsContent>
              
              {/* Connections Tab */}
              <TabsContent value="connections">
                <h2 className="text-lg font-medium text-slate-800 mb-3">People you've connected with</h2>
                
                {isLoadingMatches ? (
                  renderLoading()
                ) : !getAcceptedMatches().length ? (
                  renderEmpty('accepted')
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {getAcceptedMatches().map((match: any) => (
                      <div key={match.id} className="p-4 border border-slate-200 rounded-lg bg-white hover:bg-slate-50">
                        <div className="flex items-center">
                          <div className="w-12 h-12 rounded-full bg-primary-100 flex items-center justify-center text-primary-600">
                            {match.user.username.charAt(0).toUpperCase()}
                          </div>
                          <div className="ml-3">
                            <p className="text-sm font-medium text-slate-800">{match.user.username}</p>
                            <p className="text-xs text-slate-500">{match.user.email}</p>
                          </div>
                        </div>
                        
                        <Button
                          className="w-full mt-4"
                          onClick={() => startChat(match.id)}
                        >
                          <MessageCircle className="h-4 w-4 mr-1" />
                          Start Chat
                        </Button>
                      </div>
                    ))}
                  </div>
                )}
              </TabsContent>
              
              {/* Pending Tab */}
              <TabsContent value="pending">
                <h2 className="text-lg font-medium text-slate-800 mb-3">Connection requests waiting for your response</h2>
                
                {isLoadingMatches ? (
                  renderLoading()
                ) : !getPendingMatches().length ? (
                  renderEmpty('pending')
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {getPendingMatches().map((match: any) => (
                      <div key={match.id} className="p-4 border border-slate-200 rounded-lg bg-white hover:bg-slate-50">
                        <div className="flex items-center">
                          <div className="w-12 h-12 rounded-full bg-primary-100 flex items-center justify-center text-primary-600">
                            {match.user.username.charAt(0).toUpperCase()}
                          </div>
                          <div className="ml-3">
                            <p className="text-sm font-medium text-slate-800">{match.user.username}</p>
                            <p className="text-xs text-slate-500">{match.user.email}</p>
                          </div>
                          <Badge className="ml-auto">
                            {match.matchScore}% Match
                          </Badge>
                        </div>
                        
                        <div className="mt-4 grid grid-cols-2 gap-2">
                          <Button
                            variant="outline"
                            className="text-red-600 border-red-200 hover:bg-red-50"
                            onClick={() => rejectMatchMutation.mutate(match.id)}
                            disabled={rejectMatchMutation.isPending}
                          >
                            <UserX className="h-4 w-4 mr-1" />
                            Decline
                          </Button>
                          <Button
                            onClick={() => acceptMatchMutation.mutate(match.id)}
                            disabled={acceptMatchMutation.isPending}
                          >
                            <Users className="h-4 w-4 mr-1" />
                            Accept
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </TabsContent>
            </Tabs>
          </div>
        </div>
        
        {/* Mobile Bottom Navigation */}
        <MobileNav />
      </main>
    </div>
  );
}
