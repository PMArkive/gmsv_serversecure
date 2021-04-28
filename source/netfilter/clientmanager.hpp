#pragma once

#include "client.hpp"

#include <cstdint>
#include <memory>
#include <list>
#include <unordered_map>

namespace netfilter
{
	class ClientManager
	{
	public:
		enum class RateLimitType
		{
			None,
			Individual,
			Global
		};

		ClientManager( );

		void SetState( const bool enabled );

		RateLimitType CheckIPRate( const uint32_t address, const uint32_t time );

		uint32_t GetMaxQueriesWindow( ) const;
		uint32_t GetMaxQueriesPerSecond( ) const;
		uint32_t GetGlobalMaxQueriesPerSecond( ) const;

		void SetMaxQueriesWindow( const uint32_t window );
		void SetMaxQueriesPerSecond( const uint32_t max );
		void SetGlobalMaxQueriesPerSecond( const uint32_t max );

		static constexpr uint32_t MaxClients = 8192;
		static constexpr uint32_t SafePruneMaxClients = MaxClients * 3 / 4;
		static constexpr uint32_t LastDitchPruneMaxClients = MaxClients * 7 / 8;
		static constexpr uint32_t MaxQueriesWindow = 60;
		static constexpr uint32_t MaxQueriesPerSecond = 1;
		static constexpr uint32_t GlobalMaxQueriesPerSecond = 50;

	private:
		std::list<std::shared_ptr<Client>>::iterator FindFirstPlacementForLastPing( const uint32_t last_ping );
		std::list<std::shared_ptr<Client>>::iterator FindOptimalPlacementForLastPing( const uint32_t last_ping );
		void RemoveClientFromList( const std::shared_ptr<Client> &client );
		void SafePrune( const uint32_t time );
		void LastDitchPrune( );

		std::list<std::shared_ptr<Client>> m_clients;
		std::unordered_map<uint32_t, std::shared_ptr<Client>> m_address_map;
		bool m_enabled;
		uint32_t m_global_count;
		uint32_t m_global_last_reset;
		uint32_t m_max_window;
		uint32_t m_max_sec;
		uint32_t m_global_max_sec;
	};
}
