import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { PlusCircle, Code, Trash2, Edit, CheckCircle } from "lucide-react";
import { AddSkillDialog } from "@/components/skills/add-skill-dialog";
import { SkillQuizDialog } from "@/components/skills/skill-quiz-dialog";
import { queryClient } from "@/lib/queryClient";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AvatarIcon } from "@/components/ui/avatar-icon";

export default function SkillsManagement() {
  const [activeTab, setActiveTab] = useState<"teaching" | "learning">("teaching");
  const [isAddSkillOpen, setIsAddSkillOpen] = useState(false);
  const [isQuizOpen, setIsQuizOpen] = useState(false);
  const [selectedSkill, setSelectedSkill] = useState<any>(null);
  const { toast } = useToast();

  const { data: teachingSkills, isLoading: isTeachingLoading } = useQuery({
    queryKey: ['/api/user/skills/teaching'],
  });

  const { data: learningSkills, isLoading: isLearningLoading } = useQuery({
    queryKey: ['/api/user/skills/learning'],
  });

  const deleteSkillMutation = useMutation({
    mutationFn: async (skillId: number) => {
      return await apiRequest('DELETE', `/api/user/skills/${skillId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/user/skills/teaching'] });
      queryClient.invalidateQueries({ queryKey: ['/api/user/skills/learning'] });
      queryClient.invalidateQueries({ queryKey: ['/api/user/stats'] });
      toast({
        title: "Skill removed",
        description: "The skill has been removed from your profile.",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to remove skill",
        variant: "destructive",
      });
    }
  });

  const startVerification = (skill: any) => {
    setSelectedSkill(skill);
    setIsQuizOpen(true);
  };

  const getSkillIcon = (name: string) => {
    // Simple mapping of skill names to icons
    if (name.toLowerCase().includes('javascript')) return <Code />;
    if (name.toLowerCase().includes('react')) return <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 13.5C11.173 13.5 10.5 12.827 10.5 12C10.5 11.173 11.173 10.5 12 10.5C12.827 10.5 13.5 11.173 13.5 12C13.5 12.827 12.827 13.5 12 13.5Z" fill="currentColor"/><path d="M22.266 12C22.266 10.458 20.693 9.005 18.327 8.15C18.81 6.464 18.655 5.095 17.85 4.6C17.589 4.436 17.272 4.36 16.913 4.36V5.11C17.097 5.11 17.239 5.147 17.347 5.218C17.75 5.467 17.878 6.38 17.776 7.552C17.751 7.829 17.705 8.117 17.645 8.412C16.738 8.182 15.738 8.006 14.673 7.89C14.026 7.034 13.353 6.272 12.677 5.631C13.848 4.555 14.936 4.046 15.691 4.046V3.296C14.71 3.296 13.41 3.901 12.087 5.102C10.764 3.908 9.464 3.31 8.483 3.31V4.06C9.233 4.06 10.326 4.564 11.497 5.63C10.826 6.271 10.153 7.03 9.512 7.886C8.443 8.002 7.443 8.178 6.536 8.411C6.472 8.122 6.429 7.842 6.401 7.571C6.295 6.399 6.419 5.486 6.818 5.233C6.921 5.158 7.07 5.124 7.254 5.124V4.374C6.891 4.374 6.574 4.45 6.308 4.614C5.508 5.109 5.358 6.474 5.845 8.15C3.488 9.01 1.921 10.458 1.921 12C1.921 13.542 3.494 14.995 5.86 15.85C5.377 17.536 5.532 18.905 6.336 19.4C6.598 19.564 6.915 19.64 7.277 19.64C8.258 19.64 9.558 19.035 10.881 17.834C12.204 19.028 13.504 19.626 14.485 19.626C14.848 19.626 15.165 19.55 15.431 19.386C16.231 18.891 16.381 17.526 15.894 15.85C18.241 14.995 19.808 13.538 19.808 12H22.266ZM17.331 8.769C17.225 9.175 17.089 9.594 16.934 10.013C16.82 9.769 16.7 9.525 16.566 9.28C16.436 9.036 16.295 8.797 16.15 8.565C16.564 8.621 16.959 8.689 17.331 8.769ZM15.25 13.071C15.005 13.489 14.751 13.886 14.485 14.254C13.97 14.292 13.444 14.313 12.913 14.313C12.387 14.313 11.862 14.292 11.35 14.254C11.084 13.886 10.826 13.493 10.577 13.078C10.336 12.671 10.116 12.257 9.917 11.836C10.112 11.416 10.336 10.997 10.573 10.59C10.818 10.172 11.073 9.775 11.339 9.407C11.854 9.369 12.38 9.348 12.91 9.348C13.436 9.348 13.962 9.369 14.474 9.407C14.74 9.775 14.998 10.168 15.247 10.583C15.487 10.99 15.708 11.404 15.907 11.825C15.708 12.245 15.487 12.664 15.25 13.071ZM16.934 13.973C17.093 14.392 17.229 14.815 17.338 15.224C16.966 15.304 16.567 15.375 16.15 15.431C16.295 15.196 16.436 14.953 16.57 14.709C16.7 14.468 16.82 14.221 16.934 13.973ZM12.924 17.209C12.625 16.907 12.326 16.567 12.03 16.189C12.316 16.203 12.609 16.213 12.906 16.213C13.208 16.213 13.505 16.206 13.795 16.189C13.505 16.567 13.204 16.907 12.924 17.209ZM9.683 15.431C9.272 15.375 8.877 15.307 8.505 15.227C8.611 14.822 8.747 14.403 8.902 13.983C9.016 14.228 9.136 14.472 9.271 14.716C9.4 14.961 9.538 15.199 9.683 15.431ZM12.89 6.791C13.189 7.093 13.487 7.433 13.784 7.811C13.498 7.797 13.204 7.787 12.907 7.787C12.606 7.787 12.309 7.794 12.018 7.811C12.309 7.433 12.61 7.093 12.89 6.791ZM9.679 8.569C9.534 8.804 9.393 9.047 9.258 9.291C9.129 9.532 9.009 9.78 8.895 10.027C8.736 9.608 8.6 9.186 8.491 8.776C8.863 8.7 9.262 8.626 9.679 8.569ZM5.978 14.588C4.697 14.015 3.89 13.243 3.89 12C3.89 10.757 4.697 9.982 5.978 9.412C6.298 9.28 6.649 9.162 7.014 9.051C7.225 9.685 7.5 10.348 7.843 11.025C7.504 11.702 7.232 12.371 7.025 13.01C6.652 12.897 6.301 12.775 5.978 12.644L5.978 14.588ZM8.48 18.782C8.076 18.533 7.948 17.62 8.05 16.448C8.075 16.171 8.122 15.883 8.182 15.588C9.089 15.818 10.089 15.994 11.153 16.11C11.801 16.966 12.474 17.728 13.15 18.369C11.979 19.445 10.89 19.954 10.136 19.954C9.955 19.95 9.813 19.913 8.48 18.782ZM19.425 14.584C17.701 15.539 15.38 16.11 12.913 16.11C10.446 16.11 8.125 15.539 6.401 14.584V12.644C8.125 11.689 10.446 11.118 12.913 11.118C15.38 11.118 17.701 11.689 19.425 12.644V14.584ZM17.426 16.448C17.532 17.62 17.408 18.533 17.01 18.786C16.906 18.861 16.757 18.895 16.573 18.895C15.819 18.895 14.727 18.391 13.556 17.326C14.226 16.684 14.9 15.925 15.541 15.069C16.61 14.953 17.61 14.777 18.517 14.544C18.577 14.878 18.397 16.171 17.426 16.448Z"/></svg>;
    if (name.toLowerCase().includes('ui/ux')) return <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M7 6a7.75 7.75 0 1 0 10 0"></path><path d="M12 9v3l1.5 1.5"></path><path d="M17 3.34a10 10 0 0 1 .67 15.49"></path><path d="M21 16a11.78 11.78 0 0 1-2.95 7.74"></path><path d="M11.83 2a10 10 0 0 0 2.41 17.48"></path><path d="M13 21.7a11.78 11.78 0 0 1-10.37-1.05"></path><path d="M3 7.75a11.8 11.8 0 0 1 2.13-2.12"></path></svg>;
    
    // Default icon
    return <Code />;
  };

  const renderSkillsList = (skills: any[], isLoading: boolean) => {
    if (isLoading) {
      return Array.from({ length: 3 }).map((_, i) => (
        <div key={i} className="flex items-center justify-between p-3 bg-slate-50 rounded-md">
          <div className="flex items-center">
            <Skeleton className="w-10 h-10 rounded-full" />
            <div className="ml-3">
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-3 w-24 mt-1" />
            </div>
          </div>
        </div>
      ));
    }

    if (!skills || skills.length === 0) {
      return (
        <div className="p-8 text-center">
          <p className="text-slate-500">No skills added yet.</p>
          <Button 
            onClick={() => setIsAddSkillOpen(true)}
            variant="outline" 
            className="mt-2"
          >
            Add your first skill
          </Button>
        </div>
      );
    }

    return skills.map((skill) => (
      <div key={skill.id} className="flex items-center justify-between p-3 bg-slate-50 rounded-md">
        <div className="flex items-center">
          <AvatarIcon 
            icon={getSkillIcon(skill.skill.name)} 
          />
          <div className="ml-3">
            <p className="text-sm font-medium text-slate-800">{skill.skill.name}</p>
            <div className="flex items-center">
              {activeTab === "teaching" && (
                skill.isVerified ? (
                  <span className="text-xs bg-emerald-500 text-white px-1.5 py-0.5 rounded">Verified</span>
                ) : (
                  <span className="text-xs bg-slate-200 text-slate-700 px-1.5 py-0.5 rounded">Pending Verification</span>
                )
              )}
              <span className="ml-2 text-xs text-slate-500">{skill.proficiency}</span>
            </div>
          </div>
        </div>
        <div className="flex space-x-2">
          {activeTab === "teaching" && !skill.isVerified && (
            <button 
              onClick={() => startVerification(skill)}
              className="p-1 text-primary-600 hover:text-primary-700"
            >
              <CheckCircle className="h-4 w-4" />
            </button>
          )}
          <button className="p-1 text-slate-400 hover:text-slate-600">
            <Edit className="h-4 w-4" />
          </button>
          <button 
            onClick={() => deleteSkillMutation.mutate(skill.id)}
            className="p-1 text-slate-400 hover:text-slate-600"
          >
            <Trash2 className="h-4 w-4" />
          </button>
        </div>
      </div>
    ));
  };

  return (
    <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-slate-800">My Skills</h2>
        <Button
          size="sm"
          onClick={() => setIsAddSkillOpen(true)}
          className="h-8"
        >
          <PlusCircle className="h-4 w-4 mr-1" />
          Add Skill
        </Button>
      </div>
      
      <Tabs value={activeTab} onValueChange={(value) => setActiveTab(value as "teaching" | "learning")}>
        <TabsList className="mb-5 border-b border-slate-200 w-full justify-start">
          <TabsTrigger 
            value="teaching" 
            className="data-[state=active]:border-b-2 data-[state=active]:border-primary-600 data-[state=active]:text-primary-600 data-[state=active]:shadow-none px-4 py-2 text-sm font-medium"
          >
            Skills I Teach
          </TabsTrigger>
          <TabsTrigger 
            value="learning"
            className="data-[state=active]:border-b-2 data-[state=active]:border-primary-600 data-[state=active]:text-primary-600 data-[state=active]:shadow-none px-4 py-2 text-sm font-medium"
          >
            Skills I Want to Learn
          </TabsTrigger>
        </TabsList>
        
        <TabsContent value="teaching" className="space-y-3 mt-0">
          {renderSkillsList(teachingSkills, isTeachingLoading)}
        </TabsContent>
        
        <TabsContent value="learning" className="space-y-3 mt-0">
          {renderSkillsList(learningSkills, isLearningLoading)}
        </TabsContent>
      </Tabs>

      <AddSkillDialog 
        open={isAddSkillOpen} 
        onOpenChange={setIsAddSkillOpen} 
        skillType={activeTab}
      />

      {selectedSkill && (
        <SkillQuizDialog 
          open={isQuizOpen} 
          onOpenChange={setIsQuizOpen} 
          skill={selectedSkill}
        />
      )}
    </div>
  );
}
