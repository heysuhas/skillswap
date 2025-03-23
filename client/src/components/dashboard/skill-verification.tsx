import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { AlertCircle, Palette } from "lucide-react";
import { SkillQuizDialog } from "@/components/skills/skill-quiz-dialog";

export default function SkillVerification() {
  const [isQuizOpen, setIsQuizOpen] = useState(false);
  const [selectedSkill, setSelectedSkill] = useState<any>(null);

  const { data: teachingSkills } = useQuery({
    queryKey: ['/api/user/skills/teaching'],
  });

  const getUnverifiedSkills = () => {
    if (!teachingSkills) return [];
    return teachingSkills.filter((skill: any) => !skill.isVerified);
  };

  const unverifiedSkills = getUnverifiedSkills();

  const startVerification = (skill: any) => {
    setSelectedSkill(skill);
    setIsQuizOpen(true);
  };

  if (unverifiedSkills.length === 0) {
    return null; // Don't show the component if there are no skills to verify
  }

  return (
    <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-sm">
      <h2 className="text-lg font-semibold text-slate-800 mb-4">Verify Your Skills</h2>
      <div className="p-4 bg-amber-50 border border-amber-200 rounded-md mb-4">
        <div className="flex">
          <AlertCircle className="h-5 w-5 text-amber-600 mr-2 flex-shrink-0" />
          <p className="text-sm text-amber-800">
            You have {unverifiedSkills.length} skill{unverifiedSkills.length > 1 ? 's' : ''} that {unverifiedSkills.length > 1 ? 'need' : 'needs'} verification. Take a quick quiz to verify your expertise!
          </p>
        </div>
      </div>
      
      {unverifiedSkills.slice(0, 1).map((skill: any) => (
        <div key={skill.id} className="p-4 border border-slate-200 rounded-md">
          <div className="flex items-center">
            <div className="flex-shrink-0 w-10 h-10 rounded-full bg-primary-100 flex items-center justify-center text-primary-600">
              <Palette className="h-5 w-5" />
            </div>
            <div className="ml-3">
              <p className="text-sm font-medium text-slate-800">{skill.skill.name}</p>
              <p className="text-xs text-slate-500">10 questions • ~5 minutes</p>
            </div>
          </div>
          <Button 
            className="mt-3 w-full"
            onClick={() => startVerification(skill)}
          >
            Start Verification
          </Button>
        </div>
      ))}

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
