package route

import (
	"fmt"
	"net"

	"github.com/google/uuid"
	"github.com/ttpreport/ligolo-mp/v2/cmd/client/tui/utils"
	pb "github.com/ttpreport/ligolo-mp/v2/protobuf"
)

type Route struct {
	ID         string
	Cidr       *net.IPNet
	IsLoopback bool
	Metric     int
}

func NewRoute(cidr string, metric int, isLoopback bool) (*Route, error) {
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	return &Route{
		ID:         uuid.New().String(),
		Cidr:       dst,
		IsLoopback: isLoopback,
		Metric:     metric,
	}, nil
}

func (route *Route) String() string {
	return fmt.Sprintf("CIDR=%s, IsLoopback=%s, Metric=%d", route.Cidr.String(), utils.HumanBool(route.IsLoopback), route.Metric)
}

func (route *Route) Proto() *pb.Route {
	return &pb.Route{
		ID:         route.ID,
		Cidr:       route.Cidr.String(),
		IsLoopback: route.IsLoopback,
		Metric:     int32(route.Metric),
	}
}

func ProtoToRoute(p *pb.Route) *Route {
	_, cidr, _ := net.ParseCIDR(p.Cidr)

	return &Route{
		ID:         p.ID,
		Cidr:       cidr,
		IsLoopback: p.IsLoopback,
		Metric:     int(p.Metric),
	}
}

type Trace struct {
	IsInternal bool
	Session    string
	Iface      string
	Via        string
	Metric     uint
}

func (t *Trace) Proto() *pb.Traceroute {
	return &pb.Traceroute{
		IsInternal: t.IsInternal,
		Session:    t.Session,
		Iface:      t.Iface,
		Via:        t.Via,
		Metric:     int32(t.Metric),
	}
}

// ProbeResult represents the result of a network probe attempt
type ProbeResult struct {
	Target      string // IP address tested
	IsReachable bool   // Whether target responded
	LatencyMs   int32  // Round-trip time in milliseconds
	Method      string // Method that succeeded (e.g., "icmp", "tcp:22")
	Error       string // Error message if probe failed
}
