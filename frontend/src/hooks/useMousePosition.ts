import { useState, useEffect, RefObject } from 'react';

export function useMousePosition(ref: RefObject<HTMLElement | null>) {
    const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

    useEffect(() => {
        const handleMouseMove = (event: MouseEvent) => {
            if (ref.current) {
                const rect = ref.current.getBoundingClientRect();
                setMousePos({
                    x: event.clientX - rect.left,
                    y: event.clientY - rect.top,
                });
            }
        };

        // Attach listener to window so it updates smoothly even if moving fast
        window.addEventListener('mousemove', handleMouseMove);

        return () => {
            window.removeEventListener('mousemove', handleMouseMove);
        };
    }, [ref]);

    return mousePos;
}