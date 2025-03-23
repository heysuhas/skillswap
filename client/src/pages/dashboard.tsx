import { useQuery } from "@tanstack/react-query";

// Layout components
import Sidebar from "@/components/layout/sidebar";
import MobileSidebar from "@/components/layout/mobile-sidebar";
import MobileNav from "@/components/layout/mobile-nav";

// Dashboard components
import { StatCard } from "@/components/dashboard/stat-card";
import SkillsManagement from "@/components/dashboard/skills-management";
import MatchesList from "@/components/dashboard/matches-list";
import UpcomingSessions from "@/components/dashboard/upcoming-sessions";
import RecentMessages from "@/components/dashboard/recent-messages";
import SkillVerification from "@/components/dashboard/skill-verification";

// Icons
import { LayoutDashboard, LightbulbIcon, BookOpen, CalendarCheck2 } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";

export default function Dashboard() {
  // Fetch user stats
  const { data: stats, isLoading: isLoadingStats } = useQuery({
    queryKey: ['/api/user/stats'],
  });

  return (
    <div className="flex h-screen bg-slate-50">
      {/* Sidebar - Desktop only */}
      <Sidebar />
      
      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Mobile Header and Menu */}
        <MobileSidebar />
        
        {/* Dashboard Content */}
        <div className="flex-1 overflow-auto">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
            {/* Page Header */}
            <div className="mb-6">
              <h1 className="text-2xl font-semibold text-slate-800">Dashboard</h1>
              <p className="text-sm text-slate-500">Welcome back! Here's what's happening with your SkillSwap account.</p>
            </div>
            
            {/* Stats Overview */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
              {isLoadingStats ? (
                // Loading skeleton for stats
                Array.from({ length: 4 }).map((_, i) => (
                  <div key={i} className="bg-white p-5 rounded-lg border border-slate-200 shadow-sm">
                    <div className="flex items-center">
                      <Skeleton className="w-10 h-10 rounded-md" />
                      <div className="ml-3">
                        <Skeleton className="h-4 w-24" />
                        <Skeleton className="h-6 w-10 mt-1" />
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                // Actual stat cards
                <>
                  <StatCard 
                    title="My Matches" 
                    value={stats?.matchesCount || 0} 
                    icon={<LayoutDashboard className="h-5 w-5" />} 
                    color="primary"
                  />
                  <StatCard 
                    title="Skills I Teach" 
                    value={stats?.teachingCount || 0} 
                    icon={<LightbulbIcon className="h-5 w-5" />} 
                    color="secondary"
                  />
                  <StatCard 
                    title="Skills I Learn" 
                    value={stats?.learningCount || 0} 
                    icon={<BookOpen className="h-5 w-5" />} 
                    color="accent"
                  />
                  <StatCard 
                    title="Sessions" 
                    value={stats?.sessionsCount || 0} 
                    icon={<CalendarCheck2 className="h-5 w-5" />} 
                    color="default"
                  />
                </>
              )}
            </div>
            
            {/* Main Sections */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Skills and Matches Sections */}
              <div className="lg:col-span-2 space-y-6">
                <SkillsManagement />
                <MatchesList />
              </div>
              
              {/* Sidebar Sections */}
              <div className="space-y-6">
                <UpcomingSessions />
                <RecentMessages />
                <SkillVerification />
              </div>
            </div>
          </div>
        </div>
        
        {/* Mobile Bottom Navigation */}
        <MobileNav />
      </main>
    </div>
  );
}
