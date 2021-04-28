#include "clientmanager.hpp"
#include "debug.hpp"

namespace netfilter
{
	ClientManager::ClientManager( ) :
		m_enabled( false ), m_global_count( 0 ), m_global_last_reset( 0 ), m_max_window( MaxQueriesWindow ),
		m_max_sec( MaxQueriesPerSecond ), m_global_max_sec( GlobalMaxQueriesPerSecond )
	{ }

	void ClientManager::SetState( const bool enabled )
	{
		m_enabled = enabled;
	}

	ClientManager::RateLimitType ClientManager::CheckIPRate( const uint32_t address, const uint32_t time )
	{
		if( !m_enabled )
			return RateLimitType::None;

		const auto address_iterator = m_address_map.find( address );
		if( address_iterator != m_address_map.end( ) )
		{
			const auto &client = address_iterator->second;

			if( client->GetLastPing( ) != time )
			{
				RemoveClientFromList( client );
				m_clients.emplace( FindOptimalPlacementForLastPing( time ), client );
			}

			if( !client->CheckIPRate( time ) )
				return RateLimitType::Individual;
		}
		else
		{
			if( m_address_map.size( ) >= MaxClients )
				SafePrune( time );

			if( m_address_map.size( ) >= MaxClients )
				LastDitchPrune( );

			auto client = std::make_shared<Client>( *this, address, time );
			m_address_map.emplace( address, client );
			m_clients.emplace( FindOptimalPlacementForLastPing( time ), client );
		}

		if( time - m_global_last_reset >= m_max_window )
		{
			m_global_last_reset = time;
			m_global_count = 1;
		}
		else
		{
			++m_global_count;
			if( m_global_count >= m_global_max_sec * m_max_window )
			{
				_DebugWarning(
					"[ServerSecure] %d.%d.%d.%d reached the global query limit!\n",
					( address >> 24 ) & 0xFF,
					( address >> 16 ) & 0xFF,
					( address >> 8 ) & 0xFF,
					address & 0xFF
				);
				return RateLimitType::Global;
			}
		}

		return RateLimitType::None;
	}

	uint32_t ClientManager::GetMaxQueriesWindow( ) const
	{
		return m_max_window;
	}

	uint32_t ClientManager::GetMaxQueriesPerSecond( ) const
	{
		return m_max_sec;
	}

	uint32_t ClientManager::GetGlobalMaxQueriesPerSecond( ) const
	{
		return m_global_max_sec;
	}

	void ClientManager::SetMaxQueriesWindow( const uint32_t window )
	{
		m_max_window = window;
	}

	void ClientManager::SetMaxQueriesPerSecond( const uint32_t max )
	{
		m_max_sec = max;
	}

	void ClientManager::SetGlobalMaxQueriesPerSecond( const uint32_t max )
	{
		m_global_max_sec = max;
	}

	std::list<std::shared_ptr<Client>>::iterator ClientManager::FindFirstPlacementForLastPing( const uint32_t last_ping )
	{
		for( auto it = m_clients.begin( ); it != m_clients.end( ); ++it )
			if( it->get( )->GetLastPing( ) >= last_ping )
				return it;

		return m_clients.end( );
	}

	std::list<std::shared_ptr<Client>>::iterator ClientManager::FindOptimalPlacementForLastPing( const uint32_t last_ping )
	{
		// Uses reverse iterators because of an interesting property of time:
		// it only moves forward (as of the year 2021)
		// As such, we assume that pings that occur after other pings have a greater (or equal)
		// timestamp (at least, most of the time).
		// Knowing that the clients list is in ascending order of last ping time, searching where
		// to place a new ping from the end in reverse is, therefore, better.
		for( auto it = m_clients.rbegin( ); it != m_clients.rend( ); ++it )
			if( it->get( )->GetLastPing( ) <= last_ping )
				return it.base( );

		return m_clients.begin( );
	}

	void ClientManager::RemoveClientFromList( const std::shared_ptr<Client> &client )
	{
		const uint32_t last_ping = client->GetLastPing( );
		for( auto it = FindFirstPlacementForLastPing( last_ping ); it != m_clients.end( ); ++it )
		{
			if( it->get( )->GetLastPing( ) != last_ping )
				break;

			if( *it == client )
			{
				m_clients.erase( it );
				break;
			}
		}
	}

	// Safely remove clients that have timed out.
	void ClientManager::SafePrune( const uint32_t time )
	{
		for( auto it = m_address_map.begin( ); it != m_address_map.end( ); ++it )
		{
			const auto &client = it->second;
			if( client->TimedOut( time ) )
			{
				client->MarkForRemoval( );
				it = m_address_map.erase( it );

				if( m_address_map.size( ) <= SafePruneMaxClients )
					break;
			}
		}

		// Do a single pass to remove clients marked for removal.
		m_clients.remove_if( []( const std::shared_ptr<Client> &value )
		{
			return value->MarkedForRemoval( );
		} );
	}

	// Last ditch effort to clean up space by removing older clients.
	// Since 'm_clients' is ordered by ascending last pings, we can remove as many elements from the beginning as needed.
	void ClientManager::LastDitchPrune( )
	{
		const size_t prune_amount = m_clients.size( ) - LastDitchPruneMaxClients;
		const auto first_elem = m_clients.begin( );
		const auto last_elem = std::next( first_elem, prune_amount );

		for( auto it = first_elem; it != last_elem; ++it )
			m_address_map.erase( it->get( )->GetAddress( ) );

		m_clients.erase( first_elem, last_elem );
	}
}
