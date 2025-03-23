import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useAuth } from "@/hooks/use-auth";
import { useToast } from "@/hooks/use-toast";

// Layout components
import Sidebar from "@/components/layout/sidebar";
import MobileSidebar from "@/components/layout/mobile-sidebar";
import MobileNav from "@/components/layout/mobile-nav";

// UI components
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Separator } from "@/components/ui/separator";
import { Loader2, User } from "lucide-react";
import SkillsManagement from "@/components/dashboard/skills-management";
import { ProfilePicture } from "@/components/profile/profile-picture";

// Update profile schema
const profileFormSchema = z.object({
  username: z.string().min(3, "Username must be at least 3 characters"),
  email: z.string().email("Please enter a valid email address"),
});

// Change password schema
const passwordFormSchema = z.object({
  currentPassword: z.string().min(1, "Current password is required"),
  newPassword: z.string().min(6, "New password must be at least 6 characters"),
  confirmPassword: z.string().min(6, "Confirm password must be at least 6 characters"),
}).refine(data => data.newPassword === data.confirmPassword, {
  message: "New passwords don't match",
  path: ["confirmPassword"],
});

type ProfileFormValues = z.infer<typeof profileFormSchema>;
type PasswordFormValues = z.infer<typeof passwordFormSchema>;

export default function Profile() {
  const { user, logout } = useAuth();
  const { toast } = useToast();
  const [isUpdatingProfile, setIsUpdatingProfile] = useState(false);
  const [isChangingPassword, setIsChangingPassword] = useState(false);
  const [isUpdatingProfilePicture, setIsUpdatingProfilePicture] = useState(false);

  // Profile form
  const profileForm = useForm<ProfileFormValues>({
    resolver: zodResolver(profileFormSchema),
    defaultValues: {
      username: user?.username || "",
      email: user?.email || "",
    },
  });

  // Password form
  const passwordForm = useForm<PasswordFormValues>({
    resolver: zodResolver(passwordFormSchema),
    defaultValues: {
      currentPassword: "",
      newPassword: "",
      confirmPassword: "",
    },
  });

  // Update profile mutation
  const updateProfileMutation = useMutation({
    mutationFn: async (data: ProfileFormValues) => {
      return await apiRequest('PUT', '/api/user', data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/user'] });
      toast({
        title: "Profile updated",
        description: "Your profile has been updated successfully.",
      });
      setIsUpdatingProfile(false);
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to update profile",
        variant: "destructive",
      });
      setIsUpdatingProfile(false);
    }
  });

  // Change password mutation
  const changePasswordMutation = useMutation({
    mutationFn: async (data: PasswordFormValues) => {
      return await apiRequest('PUT', '/api/user/password', {
        currentPassword: data.currentPassword,
        newPassword: data.newPassword,
      });
    },
    onSuccess: () => {
      toast({
        title: "Password changed",
        description: "Your password has been changed successfully.",
      });
      passwordForm.reset();
      setIsChangingPassword(false);
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to change password",
        variant: "destructive",
      });
      setIsChangingPassword(false);
    }
  });
  
  // Update profile picture mutation
  const updateProfilePictureMutation = useMutation({
    mutationFn: async (profilePicture: string | null) => {
      setIsUpdatingProfilePicture(true);
      return await apiRequest('PUT', '/api/user/profile', { profilePicture });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/user'] });
      toast({
        title: "Profile picture updated",
        description: "Your profile picture has been updated successfully.",
      });
      setIsUpdatingProfilePicture(false);
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to update profile picture",
        variant: "destructive",
      });
      setIsUpdatingProfilePicture(false);
    }
  });

  // Handle profile update
  function onProfileSubmit(data: ProfileFormValues) {
    setIsUpdatingProfile(true);
    updateProfileMutation.mutate(data);
  }

  // Handle password change
  function onPasswordSubmit(data: PasswordFormValues) {
    setIsChangingPassword(true);
    changePasswordMutation.mutate(data);
  }
  
  // Handle profile picture update
  function handleProfilePictureUpdate(imageUrl: string | null) {
    updateProfilePictureMutation.mutate(imageUrl);
  }

  return (
    <div className="flex h-screen bg-slate-50">
      {/* Sidebar - Desktop only */}
      <Sidebar />
      
      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Mobile Header and Menu */}
        <MobileSidebar />
        
        {/* Profile Content */}
        <div className="flex-1 overflow-auto">
          <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
            {/* Page Header */}
            <div className="mb-6">
              <h1 className="text-2xl font-semibold text-slate-800">Profile</h1>
              <p className="text-sm text-slate-500">Manage your account information and skills</p>
            </div>
            
            <Tabs defaultValue="account" className="space-y-6">
              <TabsList className="mb-4">
                <TabsTrigger value="account">Account</TabsTrigger>
                <TabsTrigger value="skills">Skills</TabsTrigger>
              </TabsList>
              
              <TabsContent value="account" className="space-y-6">
                {/* Account Information Card */}
                <Card>
                  <CardHeader>
                    <CardTitle>Account Information</CardTitle>
                    <CardDescription>
                      Update your account details
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="flex flex-col md:flex-row gap-6 mb-6">
                      <div className="flex flex-col items-center gap-2">
                        <ProfilePicture 
                          username={user?.username || "User"} 
                          initialImage={user?.profilePicture || null} 
                          onSave={handleProfilePictureUpdate}
                          size="lg"
                        />
                        <p className="text-sm text-slate-500">Profile Picture</p>
                      </div>
                      <div className="flex-1">
                        <Form {...profileForm}>
                          <form onSubmit={profileForm.handleSubmit(onProfileSubmit)} className="space-y-4">
                            <FormField
                              control={profileForm.control}
                              name="username"
                              render={({ field }) => (
                                <FormItem>
                                  <FormLabel>Username</FormLabel>
                                  <FormControl>
                                    <Input {...field} disabled={isUpdatingProfile} />
                                  </FormControl>
                                  <FormMessage />
                                </FormItem>
                              )}
                            />
                            <FormField
                              control={profileForm.control}
                              name="email"
                              render={({ field }) => (
                                <FormItem>
                                  <FormLabel>Email</FormLabel>
                                  <FormControl>
                                    <Input {...field} disabled={isUpdatingProfile} />
                                  </FormControl>
                                  <FormMessage />
                                </FormItem>
                              )}
                            />
                            <div className="flex justify-end">
                              <Button type="submit" disabled={isUpdatingProfile}>
                                {isUpdatingProfile ? (
                                  <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    Updating...
                                  </>
                                ) : (
                                  "Update Account"
                                )}
                              </Button>
                            </div>
                          </form>
                        </Form>
                      </div>
                    </div>
                  </CardContent>
                </Card>
                
                {/* Change Password Card */}
                <Card>
                  <CardHeader>
                    <CardTitle>Change Password</CardTitle>
                    <CardDescription>
                      Update your password
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Form {...passwordForm}>
                      <form onSubmit={passwordForm.handleSubmit(onPasswordSubmit)} className="space-y-4">
                        <FormField
                          control={passwordForm.control}
                          name="currentPassword"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Current Password</FormLabel>
                              <FormControl>
                                <Input 
                                  type="password" 
                                  {...field} 
                                  disabled={isChangingPassword} 
                                />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                        <FormField
                          control={passwordForm.control}
                          name="newPassword"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>New Password</FormLabel>
                              <FormControl>
                                <Input 
                                  type="password" 
                                  {...field} 
                                  disabled={isChangingPassword} 
                                />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                        <FormField
                          control={passwordForm.control}
                          name="confirmPassword"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Confirm New Password</FormLabel>
                              <FormControl>
                                <Input 
                                  type="password" 
                                  {...field} 
                                  disabled={isChangingPassword} 
                                />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                        <div className="flex justify-end">
                          <Button type="submit" disabled={isChangingPassword}>
                            {isChangingPassword ? (
                              <>
                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                Changing Password...
                              </>
                            ) : (
                              "Change Password"
                            )}
                          </Button>
                        </div>
                      </form>
                    </Form>
                  </CardContent>
                </Card>
                
                {/* Danger Zone Card */}
                <Card className="border-destructive/20">
                  <CardHeader>
                    <CardTitle className="text-destructive">Danger Zone</CardTitle>
                    <CardDescription>
                      Actions that can't be undone
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="font-medium">Log out from all devices</h4>
                        <p className="text-sm text-slate-500">
                          This will log you out from all devices except this one
                        </p>
                      </div>
                      <Button variant="outline" className="text-destructive border-destructive/30 hover:bg-destructive/10">
                        Log out all
                      </Button>
                    </div>
                    <Separator className="my-4" />
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="font-medium">Delete account</h4>
                        <p className="text-sm text-slate-500">
                          Permanently delete your account and all your data
                        </p>
                      </div>
                      <Button variant="destructive">
                        Delete Account
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>
              
              <TabsContent value="skills">
                <SkillsManagement />
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
