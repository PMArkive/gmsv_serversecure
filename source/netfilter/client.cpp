#include "client.hpp"
#include "clientmanager.hpp"
#include "debug.hpp"

namespace netfilter
{
	Client::Client( ClientManager &manager, const uint32_t address ) :
		m_manager( manager ), m_address( address ), m_last_ping( 0 ), m_last_reset( 0 ), m_count( 0 ), m_marked_for_removal( false )
	{ }

	Client::Client( ClientManager &manager, const uint32_t address, const uint32_t time ) :
		m_manager( manager ), m_address( address ), m_last_ping( time ), m_last_reset( time ), m_count( 1 ), m_marked_for_removal( false )
	{ }

	bool Client::CheckIPRate( const uint32_t time )
	{
		m_last_ping = time;

		if( time - m_last_reset >= m_manager.GetMaxQueriesWindow( ) )
		{
			m_last_reset = time;
			m_count = 1;
		}
		else
		{
			++m_count;
			if( m_count >= m_manager.GetMaxQueriesPerSecond( ) * m_manager.GetMaxQueriesWindow( ) )
			{
				_DebugWarning(
					"[ServerSecure] %d.%d.%d.%d reached its query limit!\n",
					( m_address >> 24 ) & 0xFF,
					( m_address >> 16 ) & 0xFF,
					( m_address >> 8 ) & 0xFF,
					m_address & 0xFF
				);
				return false;
			}
		}

		return true;
	}

	uint32_t Client::GetAddress( ) const
	{
		return m_address;
	}

	uint32_t Client::GetLastPing( ) const
	{
		return m_last_ping;
	}

	bool Client::TimedOut( const uint32_t time ) const
	{
		return time - m_last_reset >= ClientManager::MaxQueriesWindow * 2;
	}

	void Client::MarkForRemoval( )
	{
		m_marked_for_removal = true;
	}

	bool Client::MarkedForRemoval( ) const
	{
		return m_marked_for_removal;
	}
}
