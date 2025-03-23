import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Loader2, X } from "lucide-react";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";

interface SkillQuizDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  skill: any;
}

export function SkillQuizDialog({ open, onOpenChange, skill }: SkillQuizDialogProps) {
  const { toast } = useToast();
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<number[]>([]);
  const [quizComplete, setQuizComplete] = useState(false);
  const [quizPassed, setQuizPassed] = useState(false);
  const [score, setScore] = useState(0);

  // Get quiz for the selected skill
  const { data: quizzes, isLoading: isLoadingQuizzes } = useQuery({
    queryKey: [`/api/skills/${skill?.skillId}/quizzes`],
    enabled: open && !!skill,
  });

  // Get quiz questions
  const quizId = quizzes?.[0]?.id;
  const { data: questions, isLoading: isLoadingQuestions } = useQuery({
    queryKey: [`/api/quizzes/${quizId}/questions`],
    enabled: open && !!quizId,
  });

  // Submit quiz attempt
  const submitQuizMutation = useMutation({
    mutationFn: async ({ quizId, score, passed }: { quizId: number, score: number, passed: boolean }) => {
      return await apiRequest('POST', `/api/quizzes/${quizId}/attempt`, { 
        score, 
        passed,
        userId: skill?.userId
      });
    },
    onSuccess: () => {
      if (quizPassed) {
        // Invalidate queries to refresh the data
        queryClient.invalidateQueries({ queryKey: ['/api/user/skills/teaching'] });
        queryClient.invalidateQueries({ queryKey: ['/api/user/stats'] });

        toast({
          title: "Skill Verified!",
          description: "You've successfully verified your expertise in this skill.",
        });
      } else {
        toast({
          title: "Quiz Failed",
          description: "You didn't pass the verification quiz. Try again later.",
        });
      }
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to submit quiz attempt",
        variant: "destructive",
      });
    }
  });

  // Handle answer selection
  const handleAnswerSelect = (questionIndex: number, answerIndex: number) => {
    const newAnswers = [...selectedAnswers];
    newAnswers[questionIndex] = answerIndex;
    setSelectedAnswers(newAnswers);
  };

  // Navigate to next question
  const handleNext = () => {
    if (currentQuestion < (questions?.length || 0) - 1) {
      setCurrentQuestion(currentQuestion + 1);
    } else {
      // Calculate score
      let correctAnswers = 0;
      questions?.forEach((question: any, index: number) => {
        if (selectedAnswers[index] === question.correctAnswerIndex) {
          correctAnswers++;
        }
      });

      const calculatedScore = Math.round((correctAnswers / questions?.length) * 10);
      const quiz = quizzes?.[0];
      const passed = calculatedScore >= (quiz?.passingScore || 7);

      setScore(calculatedScore);
      setQuizPassed(passed);
      setQuizComplete(true);

      // Submit quiz attempt
      if (quiz) {
        submitQuizMutation.mutate({
          quizId: quiz.id,
          score: calculatedScore,
          passed
        });
      }
    }
  };

  // Navigate to previous question
  const handlePrevious = () => {
    if (currentQuestion > 0) {
      setCurrentQuestion(currentQuestion - 1);
    }
  };

  // Close dialog and reset state
  const handleClose = () => {
    onOpenChange(false);
    setTimeout(() => {
      setCurrentQuestion(0);
      setSelectedAnswers([]);
      setQuizComplete(false);
      setQuizPassed(false);
      setScore(0);
    }, 300);
  };

  // Loading state
  const isLoading = isLoadingQuizzes || isLoadingQuestions || !questions;

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-[500px] max-h-[90vh] overflow-auto">
        <DialogHeader>
          <DialogTitle className="flex justify-between items-center">
            <span>{skill?.skill?.name} Verification</span>
            <Button 
              variant="ghost" 
              size="sm" 
              onClick={handleClose} 
              className="h-8 w-8 p-0"
            >
              <X className="h-4 w-4" />
            </Button>
          </DialogTitle>
        </DialogHeader>
        
        {isLoading ? (
          <div className="flex flex-col items-center justify-center py-8">
            <Loader2 className="h-8 w-8 animate-spin text-primary-600 mb-4" />
            <p className="text-sm text-slate-500">Loading quiz questions...</p>
          </div>
        ) : quizComplete ? (
          // Quiz Results
          <div className="py-4">
            <div className={`p-4 rounded-md mb-4 ${quizPassed ? 'bg-green-50 border border-green-200' : 'bg-red-50 border border-red-200'}`}>
              <h3 className={`text-lg font-medium ${quizPassed ? 'text-green-800' : 'text-red-800'}`}>
                {quizPassed ? 'Congratulations!' : 'Quiz Failed'}
              </h3>
              <p className="text-sm mt-1">
                {quizPassed 
                  ? 'You passed the verification quiz! Your skill has been verified.'
                  : 'You did not pass the verification quiz. Try again later.'}
              </p>
            </div>
            
            <div className="text-center mb-4">
              <p className="text-sm text-slate-500">Your score</p>
              <p className="text-3xl font-bold text-slate-800">{score}/10</p>
              <p className="text-sm text-slate-500 mt-1">
                {quizPassed 
                  ? 'Score meets or exceeds the required passing score.'
                  : 'Required passing score: 7/10'}
              </p>
            </div>
            
            <div className="flex justify-center mt-6">
              <Button onClick={handleClose}>
                Close
              </Button>
            </div>
          </div>
        ) : (
          // Quiz Questions
          <div className="py-4">
            <div className="mb-5">
              <p className="text-sm text-slate-500 mb-2">
                Question {currentQuestion + 1} of {questions?.length}
              </p>
              <Progress 
                value={((currentQuestion + 1) / (questions?.length || 1)) * 100} 
                className="h-1.5"
              />
            </div>
            
            {questions && questions[currentQuestion] && (
              <div className="mb-5">
                <h4 className="text-base font-medium text-slate-800 mb-3">
                  {questions[currentQuestion].questionText}
                </h4>
                
                <RadioGroup
                  value={selectedAnswers[currentQuestion]?.toString()}
                  onValueChange={(value) => handleAnswerSelect(currentQuestion, parseInt(value))}
                  className="space-y-2"
                >
                  {questions[currentQuestion].options.map((option: string, index: number) => (
                    <div key={index} className="flex items-center p-3 border border-slate-200 rounded-md hover:bg-slate-50">
                      <RadioGroupItem value={index.toString()} id={`option-${index}`} className="mr-3" />
                      <Label htmlFor={`option-${index}`} className="w-full cursor-pointer text-sm text-slate-700">
                        {option}
                      </Label>
                    </div>
                  ))}
                </RadioGroup>
              </div>
            )}
            
            <div className="flex justify-between">
              <Button 
                type="button" 
                variant="outline" 
                onClick={handlePrevious}
                disabled={currentQuestion === 0}
              >
                Previous
              </Button>
              <Button 
                type="button"
                onClick={handleNext}
                disabled={selectedAnswers[currentQuestion] === undefined}
              >
                {currentQuestion < (questions?.length || 0) - 1 ? 'Next' : 'Submit'}
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
