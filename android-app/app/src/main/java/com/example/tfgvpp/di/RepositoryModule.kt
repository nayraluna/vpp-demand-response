package com.example.tfgvpp.di

import com.example.tfgvpp.data.repository.ApplianceRepositoryImpl
import com.example.tfgvpp.data.repository.AvailabilityRepositoryImpl
import com.example.tfgvpp.data.repository.ParticipationRepositoryImpl
import com.example.tfgvpp.data.repository.UserRepositoryImpl
import com.example.tfgvpp.domain.repository.ApplianceRepository
import com.example.tfgvpp.domain.repository.AvailabilityRepository
import com.example.tfgvpp.domain.repository.ParticipationRepository
import com.example.tfgvpp.domain.repository.UserRepository
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
abstract class RepositoryModule {

    @Binds
    @Singleton
    abstract fun bindUserRepository(impl: UserRepositoryImpl): UserRepository

    @Binds
    @Singleton
    abstract fun bindApplianceRepository(impl: ApplianceRepositoryImpl): ApplianceRepository

    @Binds
    @Singleton
    abstract fun bindAvailabilityRepository(impl: AvailabilityRepositoryImpl): AvailabilityRepository

    @Binds
    @Singleton
    abstract fun bindParticipationRepository(impl: ParticipationRepositoryImpl): ParticipationRepository
}
