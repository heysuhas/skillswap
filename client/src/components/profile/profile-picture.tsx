import { useState, useRef } from "react";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarImage, AvatarFallback } from "@/components/ui/avatar";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Camera, Upload, X } from "lucide-react";

interface ProfilePictureProps {
  username: string;
  initialImage?: string | null;
  onSave: (imageUrl: string | null) => void;
  onSkip?: () => void;
  showSkip?: boolean;
  size?: "sm" | "md" | "lg";
  className?: string;
}

export function ProfilePicture({
  username,
  initialImage,
  onSave,
  onSkip,
  showSkip = false,
  size = "md",
  className = "",
}: ProfilePictureProps) {
  const [image, setImage] = useState<string | null>(initialImage || null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();

  // Size classes based on size prop
  const sizeClasses = {
    sm: "w-10 h-10",
    md: "w-16 h-16",
    lg: "w-24 h-24",
  };

  // Get initials from username
  const getInitials = (name: string) => {
    return name
      .split(" ")
      .map((n) => n[0])
      .join("")
      .toUpperCase()
      .substring(0, 2);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // File size validation (max 5MB)
    if (file.size > 5 * 1024 * 1024) {
      toast({
        title: "File too large",
        description: "Please select an image under 5MB",
        variant: "destructive",
      });
      return;
    }

    setSelectedFile(file);

    // Create preview URL
    const reader = new FileReader();
    reader.onloadend = () => {
      setImage(reader.result as string);
    };
    reader.readAsDataURL(file);
  };

  const handleUpload = async () => {
    if (!selectedFile) return;

    setIsUploading(true);
    try {
      // In a real app, this would upload to a server
      // For this prototype, we'll just use the data URL
      const imageUrl = image;
      
      onSave(imageUrl);
      setIsDialogOpen(false);
      
      toast({
        title: "Profile picture updated",
        description: "Your profile picture has been updated successfully",
      });
    } catch (error) {
      toast({
        title: "Upload failed",
        description: "There was an error uploading your profile picture",
        variant: "destructive",
      });
    } finally {
      setIsUploading(false);
    }
  };

  const handleSkip = () => {
    if (onSkip) {
      onSkip();
    }
    setIsDialogOpen(false);
  };

  const handleRemove = () => {
    setImage(null);
    setSelectedFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  return (
    <>
      <Avatar
        className={`${sizeClasses[size]} cursor-pointer ${className}`}
        onClick={() => setIsDialogOpen(true)}
      >
        {image ? (
          <AvatarImage src={image} alt={username} />
        ) : (
          <AvatarFallback className="bg-primary-100 text-primary-600">
            {getInitials(username)}
          </AvatarFallback>
        )}
      </Avatar>

      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent className="sm:max-w-[425px]">
          <DialogHeader>
            <DialogTitle>Profile Picture</DialogTitle>
          </DialogHeader>

          <div className="flex flex-col items-center space-y-4 py-4">
            <div className="relative">
              <Avatar className="w-32 h-32">
                {image ? (
                  <AvatarImage src={image} alt={username} />
                ) : (
                  <AvatarFallback className="bg-primary-100 text-primary-600 text-3xl">
                    {getInitials(username)}
                  </AvatarFallback>
                )}
              </Avatar>
              
              {image && (
                <button
                  type="button"
                  className="absolute top-0 right-0 bg-white rounded-full shadow-md p-1 transform translate-x-2 -translate-y-2"
                  onClick={handleRemove}
                >
                  <X className="h-4 w-4" />
                </button>
              )}
            </div>

            <div className="flex gap-2">
              <Button
                variant="outline"
                onClick={() => fileInputRef.current?.click()}
              >
                <Upload className="h-4 w-4 mr-2" />
                Upload Image
              </Button>
              
              <input
                type="file"
                ref={fileInputRef}
                className="hidden"
                accept="image/*"
                onChange={handleFileChange}
              />
              
              <Button
                disabled={!selectedFile || isUploading}
                onClick={handleUpload}
              >
                {isUploading ? "Saving..." : "Save"}
              </Button>
            </div>
            
            {showSkip && (
              <Button
                variant="ghost"
                onClick={handleSkip}
                className="mt-2"
              >
                Skip for now
              </Button>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}