import { useToast as useToastShadcn } from "@/components/ui/use-toast"

export const useToast = useToastShadcn

export function toast({ ...props }: Parameters<typeof useToastShadcn>[0]) {
  return useToastShadcn().toast(props)
}
