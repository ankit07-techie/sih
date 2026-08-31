import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const buttonVariants = cva(
  "inline-flex items-center justify-center rounded-lg border border-transparent text-sm font-medium transition-colors outline-none select-none disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default: 'bg-[#21618b] text-[#f1f8fc] hover:bg-[#2e78aa] border-[#397daf]',
        outline: 'border-[#294157] bg-[#0d1b2b] text-[#a8bed0] hover:bg-[#102a40]',
        secondary: 'bg-[#0d1b2b] text-[#a8bed0] border-[#294157] hover:bg-[#102a40]',
        ghost: 'hover:bg-[#102a40] text-[#a8bed0]',
        destructive: 'bg-[#e06b62] text-white hover:bg-[#c95850]',
        link: 'text-[#75b7e5] underline-offset-4 hover:underline',
      },
      size: {
        default: 'h-9 px-4 py-2 text-xs',
        sm: 'h-8 px-3 text-xs',
        lg: 'h-10 px-6 text-sm',
        icon: 'h-9 w-9',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => {
    return (
      <button
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  }
);
Button.displayName = 'Button';

export { Button, buttonVariants };
