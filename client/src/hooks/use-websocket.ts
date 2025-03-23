import { useState, useEffect, useRef, useCallback } from 'react';
import { useAuth } from './use-auth';

interface UseWebSocketOptions {
  onMessage?: (data: any) => void;
  onOpen?: () => void;
  onClose?: () => void;
  onError?: (error: Event) => void;
  autoReconnect?: boolean;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
}

interface UseWebSocketReturn {
  socket: WebSocket | null;
  isConnected: boolean;
  sendMessage: (data: any) => void;
  reconnect: () => void;
}

export function useWebSocket(
  options: UseWebSocketOptions = {}
): UseWebSocketReturn {
  const {
    onMessage,
    onOpen,
    onClose,
    onError,
    autoReconnect = true,
    reconnectInterval = 3000,
    maxReconnectAttempts = 5,
  } = options;

  const { token } = useAuth();
  const [socket, setSocket] = useState<WebSocket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const reconnectAttempts = useRef(0);
  const reconnectTimeoutId = useRef<number | null>(null);

  // Create a WebSocket connection
  const connect = useCallback(() => {
    if (!token) return;

    // Close existing socket if any
    if (socket) {
      socket.close();
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws?token=${token}`;
    const newSocket = new WebSocket(wsUrl);

    newSocket.onopen = () => {
      console.log('WebSocket connected');
      setIsConnected(true);
      reconnectAttempts.current = 0;
      if (onOpen) onOpen();
    };

    newSocket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (onMessage) onMessage(data);
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    };

    newSocket.onclose = (event) => {
      console.log('WebSocket closed', event.code, event.reason);
      setIsConnected(false);
      setSocket(null);
      if (onClose) onClose();

      // Attempt to reconnect if enabled
      if (autoReconnect && reconnectAttempts.current < maxReconnectAttempts) {
        console.log(`Reconnecting... Attempt ${reconnectAttempts.current + 1}`);
        if (reconnectTimeoutId.current !== null) {
          window.clearTimeout(reconnectTimeoutId.current);
        }
        reconnectTimeoutId.current = window.setTimeout(() => {
          reconnectAttempts.current += 1;
          connect();
        }, reconnectInterval);
      }
    };

    newSocket.onerror = (error) => {
      console.error('WebSocket error:', error);
      if (onError) onError(error);
    };

    setSocket(newSocket);
  }, [token, socket, onOpen, onMessage, onClose, onError, autoReconnect, maxReconnectAttempts, reconnectInterval]);

  // Send a message through the WebSocket
  const sendMessage = useCallback(
    (data: any) => {
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify(data));
      } else {
        console.error('Cannot send message: WebSocket is not connected');
      }
    },
    [socket]
  );

  // Manual reconnect function
  const reconnect = useCallback(() => {
    if (reconnectTimeoutId.current !== null) {
      window.clearTimeout(reconnectTimeoutId.current);
      reconnectTimeoutId.current = null;
    }
    reconnectAttempts.current = 0;
    connect();
  }, [connect]);

  // Connect when the component mounts or token changes
  useEffect(() => {
    if (token) {
      connect();
    }

    // Cleanup function
    return () => {
      if (reconnectTimeoutId.current !== null) {
        window.clearTimeout(reconnectTimeoutId.current);
      }
      if (socket) {
        socket.close();
      }
    };
  }, [token, connect, socket]);

  return { socket, isConnected, sendMessage, reconnect };
}
