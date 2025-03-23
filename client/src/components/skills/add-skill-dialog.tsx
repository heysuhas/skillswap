import { useState, useEffect } from "react";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Loader2 } from "lucide-react";

// Form schema for adding a skill
const skillFormSchema = z.object({
  skillId: z.string().min(1, "Please select a skill"),
  proficiency: z.string().min(1, "Please select a proficiency level"),
  isTeaching: z.boolean()
});

type SkillFormValues = z.infer<typeof skillFormSchema>;

interface AddSkillDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  skillType: "teaching" | "learning";
}

export function AddSkillDialog({ open, onOpenChange, skillType }: AddSkillDialogProps) {
  const { toast } = useToast();
  const isTeaching = skillType === "teaching";

  // Get all available skills
  const { data: skills, isLoading: isLoadingSkills } = useQuery({
    queryKey: ['/api/skills'],
  });

  // Form setup
  const form = useForm<SkillFormValues>({
    resolver: zodResolver(skillFormSchema),
    defaultValues: {
      skillId: "",
      proficiency: "",
      isTeaching: isTeaching
    },
  });

  // Reset form when dialog opens/closes or skill type changes
  useEffect(() => {
    form.reset({
      skillId: "",
      proficiency: "",
      isTeaching: isTeaching
    });
  }, [open, skillType, form]);

  // Add skill mutation
  const addSkillMutation = useMutation({
    mutationFn: async (data: SkillFormValues) => {
      return await apiRequest('POST', '/api/user/skills', {
        skillId: parseInt(data.skillId),
        proficiency: data.proficiency,
        isTeaching: data.isTeaching
      });
    },
    onSuccess: () => {
      // Invalidate queries to refresh the data
      queryClient.invalidateQueries({ queryKey: ['/api/user/skills/teaching'] });
      queryClient.invalidateQueries({ queryKey: ['/api/user/skills/learning'] });
      queryClient.invalidateQueries({ queryKey: ['/api/user/stats'] });
      
      onOpenChange(false);
      form.reset();
      
      toast({
        title: "Skill added",
        description: `The skill has been added to your ${isTeaching ? "teaching" : "learning"} list.`,
      });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to add skill",
        variant: "destructive",
      });
    }
  });

  function onSubmit(data: SkillFormValues) {
    addSkillMutation.mutate(data);
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>Add a {isTeaching ? "Teaching" : "Learning"} Skill</DialogTitle>
          <DialogDescription>
            {isTeaching 
              ? "Add a skill that you can teach to others."
              : "Add a skill that you want to learn from others."}
          </DialogDescription>
        </DialogHeader>
        
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="skillId"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Skill</FormLabel>
                  <Select 
                    onValueChange={field.onChange} 
                    defaultValue={field.value}
                    disabled={isLoadingSkills}
                  >
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select a skill" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {skills?.map((skill: any) => (
                        <SelectItem key={skill.id} value={skill.id.toString()}>
                          {skill.name}
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
              name="proficiency"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Proficiency Level</FormLabel>
                  <Select onValueChange={field.onChange} defaultValue={field.value}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select proficiency level" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="Beginner">Beginner</SelectItem>
                      <SelectItem value="Intermediate">Intermediate</SelectItem>
                      <SelectItem value="Advanced">Advanced</SelectItem>
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
                onClick={() => onOpenChange(false)}
                disabled={addSkillMutation.isPending}
              >
                Cancel
              </Button>
              <Button 
                type="submit"
                disabled={addSkillMutation.isPending}
              >
                {addSkillMutation.isPending && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                Add Skill
              </Button>
            </div>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
