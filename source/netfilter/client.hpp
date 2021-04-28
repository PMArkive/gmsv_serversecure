#pragma once

#include <cstdint>

namespace netfilter
{
	class ClientManager;

	class Client
	{
	public:
		Client( ClientManager &manager, const uint32_t address );
		Client( ClientManager &manager, const uint32_t address, const uint32_t time );

		bool CheckIPRate( const uint32_t time );

		uint32_t GetAddress( ) const;
		uint32_t GetLastPing( ) const;
		bool TimedOut( const uint32_t time ) const;

		void MarkForRemoval( );
		bool MarkedForRemoval( ) const;

	private:
		ClientManager &m_manager;
		uint32_t m_address;
		uint32_t m_last_ping;
		uint32_t m_last_reset;
		uint32_t m_count;
		bool m_marked_for_removal;
	};
}
