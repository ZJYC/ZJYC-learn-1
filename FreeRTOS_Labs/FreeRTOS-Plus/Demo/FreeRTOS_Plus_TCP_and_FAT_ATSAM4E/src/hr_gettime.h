/*
*/

#ifndef HR_GETTTIME_H

#define HR_GETTTIME_H

/* SAM4E: Timer initialization function */
void vStartHighResolutionTimer( void );

uint64_t ullGetHighResolutionTime( void );

#endif /* HR_GETTTIME_H */