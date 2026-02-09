'use client';

import React, { memo, useState } from 'react';
import { Handle, Position, useReactFlow } from 'reactflow';
import { ToolNodeData } from '@/types/workflow';
import * as LucideIcons from 'lucide-react';
import { X } from 'lucide-react';

interface ToolNodeProps {
    id: string;
    data: ToolNodeData;
    selected?: boolean;
    isConnectable?: boolean;
}

/**
 * Custom Tool Node for ReactFlow
 * Displays a PDF tool as a draggable node in the workflow
 */
const ToolNode = memo(({ id, data, selected = false, isConnectable = true }: ToolNodeProps) => {
    const [isHovered, setIsHovered] = useState(false);
    const { deleteElements } = useReactFlow();

    // Get the icon component dynamically
    const iconName = toPascalCase(data.icon);
    const IconComponent = (LucideIcons as unknown as Record<string, React.ComponentType<{ className?: string }>>)[iconName]
        || LucideIcons.FileText;

    // Handle delete node
    const handleDelete = (event: React.MouseEvent) => {
        event.stopPropagation(); // Prevent node click from triggering
        deleteElements({ nodes: [{ id }] });
    };

    // Status colors
    const statusColors = {
        idle: 'bg-[hsl(var(--color-muted))]',
        processing: 'bg-blue-100 border-blue-400',
        complete: 'bg-green-100 border-green-400',
        error: 'bg-red-100 border-red-400',
    };

    // Status indicator colors
    const statusIndicatorColors = {
        idle: 'bg-gray-300',
        processing: 'bg-blue-500 animate-pulse',
        complete: 'bg-green-500',
        error: 'bg-red-500',
    };

    // Category colors
    const categoryColors: Record<string, string> = {
        'organize-manage': 'border-l-blue-500',
        'edit-annotate': 'border-l-purple-500',
        'convert-to-pdf': 'border-l-green-500',
        'convert-from-pdf': 'border-l-orange-500',
        'optimize-repair': 'border-l-yellow-500',
        'security-privacy': 'border-l-red-500',
    };

    return (
        <div
            className={`
        relative px-4 py-3 rounded-lg shadow-md border-2 border-l-4 transition-all duration-200
        ${statusColors[data.status]}
        ${categoryColors[data.category] || 'border-l-gray-500'}
        ${selected ? 'ring-2 ring-[hsl(var(--color-primary))] ring-offset-2' : ''}
        ${isHovered ? 'shadow-lg scale-[1.02]' : ''}
        min-w-[160px] max-w-[200px]
      `}
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
        >
            {/* Delete Button - shown on hover */}
            {isHovered && (
                <button
                    onClick={handleDelete}
                    className="absolute -top-2 -right-2 w-5 h-5 bg-red-500 hover:bg-red-600 rounded-full flex items-center justify-center shadow-md transition-colors z-10"
                    title="Delete node"
                >
                    <X className="w-3 h-3 text-white" />
                </button>
            )}

            {/* Input Handle */}
            <Handle
                type="target"
                position={Position.Left}
                isConnectable={isConnectable}
                className="!w-3 !h-3 !bg-[hsl(var(--color-primary))] !border-2 !border-white"
            />

            {/* Content */}
            <div className="flex items-center gap-3">
                {/* Icon */}
                <div className={`
          p-2 rounded-lg
          ${data.status === 'processing' ? 'bg-blue-200' : 'bg-white/80'}
        `}>
                    <IconComponent className="w-5 h-5 text-[hsl(var(--color-foreground))]" />
                </div>

                {/* Label and Status */}
                <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-[hsl(var(--color-foreground))] truncate">
                        {data.label}
                    </p>
                    <div className="flex items-center gap-1.5 mt-0.5">
                        <div className={`w-2 h-2 rounded-full ${statusIndicatorColors[data.status]}`} />
                        <span className="text-xs text-[hsl(var(--color-muted-foreground))] capitalize">
                            {data.status}
                        </span>
                    </div>
                </div>
            </div>

            {/* Progress bar */}
            {data.status === 'processing' && (
                <div className="mt-2 w-full h-1.5 bg-gray-200 rounded-full overflow-hidden">
                    <div
                        className="h-full bg-blue-500 rounded-full transition-all duration-300"
                        style={{ width: `${data.progress}%` }}
                    />
                </div>
            )}

            {/* Error message */}
            {data.status === 'error' && data.error && (
                <p className="mt-2 text-xs text-red-600 truncate">
                    {data.error}
                </p>
            )}

            {/* Output file count indicator */}
            {data.status === 'complete' && data.outputFiles && data.outputFiles.length > 0 && (
                <div className="mt-2 flex items-center gap-1.5">
                    <LucideIcons.Download className="w-3 h-3 text-green-600" />
                    <span className="text-[10px] text-green-600 font-medium">
                        {data.outputFiles.length} file{data.outputFiles.length > 1 ? 's' : ''}
                    </span>
                </div>
            )}

            {/* Format tags */}
            <div className="flex flex-wrap gap-1 mt-2">
                <span className="text-[10px] px-1.5 py-0.5 bg-gray-200 rounded text-gray-600">
                    in: {data.acceptedFormats.slice(0, 2).join(', ')}
                    {data.acceptedFormats.length > 2 && '...'}
                </span>
                <span className="text-[10px] px-1.5 py-0.5 bg-blue-100 rounded text-blue-600">
                    out: {data.outputFormat}
                </span>
            </div>

            {/* Output Handle */}
            <Handle
                type="source"
                position={Position.Right}
                isConnectable={isConnectable}
                className="!w-3 !h-3 !bg-[hsl(var(--color-primary))] !border-2 !border-white"
            />
        </div>
    );
});

ToolNode.displayName = 'ToolNode';

/**
 * Convert kebab-case to PascalCase for icon lookup
 */
function toPascalCase(str: string): string {
    return str
        .split('-')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join('');
}

export default ToolNode;

